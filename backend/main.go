package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB
var phoneRegex = regexp.MustCompile(`^0\d{8,10}$`)
var jwtSecret = []byte("change-this-secret-in-production")
var uploadDir = "uploads"

func canonicalRole(role string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(role))
	normalized = strings.ReplaceAll(normalized, "_", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	switch normalized {
	case "admin", "administrator", "agent", "staff", "support", "เจ้าหน้าที่", "แอดมิน":
		return "Admin", true
	case "customer", "client", "member", "user", "ลูกค้า", "ผู้ใช้":
		return "customer", true
	default:
		return "", false
	}
}

func ConnectDatabase() {
	// Try to get DSN from environment variable (for Cloud)
	dsn := os.Getenv("DATABASE_URL")

	// If not found, fallback to localhost (for local development)
	if dsn == "" {
		dsn = "shop_user:1234@tcp(127.0.0.1:3306)/ticket_db?charset=utf8mb4&parseTime=True&loc=Local"
	}

	// Important for TiDB Cloud: Add tls=true if using TiDB Cloud specific DSN
	if strings.Contains(dsn, "tidbcloud.com") && !strings.Contains(dsn, "tls=") {
		if strings.Contains(dsn, "?") {
			dsn += "&tls=true"
		} else {
			dsn += "?tls=true"
		}
	}

	database, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatal("Failed to connect to database!", err)
	}

	err = database.AutoMigrate(&User{}, &Ticket{}, &TicketReply{}, &ActivityLog{})
	if err != nil {
		log.Fatal("Failed to migrate database!", err)
	}

	DB = database

}

func logActivity(userID uint, userName, role, action, details, ip string) {
	log := ActivityLog{
		UserID:    userID,
		UserName:  userName,
		Role:      role,
		Action:    action,
		Details:   details,
		IPAddress: ip,
	}
	DB.Create(&log)
}

func resolveUploadDir() string {
	dir := strings.TrimSpace(os.Getenv("UPLOAD_DIR"))
	if dir == "" {
		if strings.EqualFold(strings.TrimSpace(os.Getenv("RENDER")), "true") {
			return "/var/data/uploads"
		}
		return "uploads"
	}
	return filepath.Clean(dir)
}

func attachmentDiskPath(attachmentPath string) string {
	normalized := strings.TrimSpace(attachmentPath)
	normalized = strings.TrimPrefix(normalized, "/")
	normalized = strings.TrimPrefix(normalized, "uploads/")
	fileName := filepath.Base(normalized)
	if fileName == "." || fileName == "" {
		return ""
	}
	return filepath.Join(uploadDir, fileName)
}

func main() {
	ConnectDatabase()
	r := gin.Default()
	uploadDir = resolveUploadDir()

	// Serve Frontend (SPA) logic is now handled by NoRoute at the end of main()

	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		log.Fatal("Failed to create uploads directory", err)
	}

	r.Static("/uploads", uploadDir)

	r.Use(cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			if origin == "" {
				return true
			}
			if origin == "http://localhost:4200" || origin == "http://127.0.0.1:4200" ||
				origin == "http://localhost:5173" || origin == "http://127.0.0.1:5173" {
				return true
			}
			if (strings.HasPrefix(origin, "http://192.168.") || strings.HasPrefix(origin, "http://10.")) &&
				(strings.HasSuffix(origin, ":4200") || strings.HasSuffix(origin, ":5173")) {
				return true
			}
			return false
		},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders: []string{
			"Content-Length",
		},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	api := r.Group("/api")
	{
		api.POST("/Admin/login", func(c *gin.Context) {
			var payload struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}

			if err := c.ShouldBindJSON(&payload); err != nil || payload.Email == "" || payload.Password == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_credentials"})
				return
			}

			email := strings.TrimSpace(payload.Email)

			var user User
			if err := DB.Where("email = ?", email).First(&user).Error; err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
				return
			}
			role, ok := canonicalRole(user.Role)
			if !ok || role != "Admin" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
				return
			}

			if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.Password)); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
				return
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub":  user.ID,
				"role": role,
				"name": user.Name,
				"exp":  time.Now().Add(24 * time.Hour).Unix(),
			})

			tokenString, err := token.SignedString(jwtSecret)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_generate_token"})
				return
			}

			logActivity(user.ID, user.Name, role, "LOGIN", "ผู้ดูแลระบบเข้าสู่ระบบสำเร็จ", c.ClientIP())

			c.JSON(http.StatusOK, gin.H{
				"token": tokenString,
				"name":  user.Name,
			})
		})

		api.POST("/Admin/login-by-email", func(c *gin.Context) {
			var payload struct {
				Email string `json:"email"`
			}

			if err := c.ShouldBindJSON(&payload); err != nil || strings.TrimSpace(payload.Email) == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
				return
			}

			email := strings.TrimSpace(payload.Email)

			var user User
			if err := DB.Where("email = ?", email).First(&user).Error; err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
				return
			}
			role, ok := canonicalRole(user.Role)
			if !ok || role != "Admin" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
				return
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub":  user.ID,
				"role": role,
				"name": user.Name,
				"exp":  time.Now().Add(24 * time.Hour).Unix(),
			})

			tokenString, err := token.SignedString(jwtSecret)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_generate_token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"token": tokenString,
				"name":  user.Name,
			})
		})

		api.POST("/customer/register", func(c *gin.Context) {
			var payload struct {
				Name     string `json:"name"`
				Email    string `json:"email"`
				Password string `json:"password"`
			}

			if err := c.ShouldBindJSON(&payload); err != nil ||
				strings.TrimSpace(payload.Name) == "" ||
				strings.TrimSpace(payload.Email) == "" ||
				strings.TrimSpace(payload.Password) == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
				return
			}

			var existing User
			if err := DB.Where("email = ?", payload.Email).First(&existing).Error; err == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "email_already_used"})
				return
			}

			hash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_hash_password"})
				return
			}

			user := User{
				Name:         strings.TrimSpace(payload.Name),
				Email:        strings.TrimSpace(payload.Email),
				Role:         "customer",
				PasswordHash: string(hash),
			}

			if err := DB.Create(&user).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_create_user"})
				return
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub":  user.ID,
				"role": user.Role,
				"name": user.Name,
				"exp":  time.Now().Add(24 * time.Hour).Unix(),
			})

			tokenString, err := token.SignedString(jwtSecret)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_generate_token"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"token": tokenString,
				"name":  user.Name,
				"role":  user.Role,
			})
		})

		api.POST("/customer/login", func(c *gin.Context) {
			fmt.Println("\n=== LOGIN ATTEMPT START ===")
			var payload struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}

			if err := c.ShouldBindJSON(&payload); err != nil || payload.Email == "" || payload.Password == "" {
				fmt.Printf("Login Error: Invalid Payload. Email: '%s'\n", payload.Email)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_credentials"})
				return
			}
			fmt.Printf("Checking user: '%s' (Password length: %d)\n", payload.Email, len(payload.Password))

			var user User
			if err := DB.Where("email = ?", strings.TrimSpace(payload.Email)).First(&user).Error; err != nil {
				fmt.Printf("Login Error: User not found in DB. Error: %v\n", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
				return
			}
			fmt.Printf("User Found: ID=%d, Role='%s', HashLength=%d\n", user.ID, user.Role, len(user.PasswordHash))

			role, ok := canonicalRole(user.Role)
			if !ok {
				fmt.Printf("Login Warning: Unsupported Role '%s' -> fallback to customer\n", user.Role)
				role = "customer"
			}
			if user.Role != role {
				DB.Model(&user).Update("role", role)
			}

			if user.PasswordHash == "" {
				fmt.Println("Login Error: PasswordHash is empty in DB")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
				return
			}

			if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.Password)); err != nil {
				fmt.Printf("Login Error: Password Mismatch! Error: %v\n", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
				return
			}
			fmt.Println("Password Check: SUCCESS")

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub":  user.ID,
				"role": role,
				"name": user.Name,
				"exp":  time.Now().Add(24 * time.Hour).Unix(),
			})

			tokenString, err := token.SignedString(jwtSecret)
			if err != nil {
				fmt.Printf("Login Error: Token Gen Failed: %v\n", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_generate_token"})
				return
			}

			fmt.Println("Login SUCCESS: Token returned.")
			fmt.Println("=== LOGIN ATTEMPT END ===")

			logActivity(user.ID, user.Name, role, "LOGIN", "ลูกค้าเข้าสู่ระบบสำเร็จ", c.ClientIP())

			c.JSON(http.StatusOK, gin.H{
				"token": tokenString,
				"name":  user.Name,
				"role":  role,
			})
		})

		api.GET("/agents", func(c *gin.Context) {
			var agents []struct {
				ID    uint   `json:"id"`
				Name  string `json:"name"`
				Email string `json:"email"`
			}

			if err := DB.Model(&User{}).
				Where("role = ?", "Admin").
				Select("id, name, email").
				Scan(&agents).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_load_agents"})
				return
			}

			c.JSON(http.StatusOK, agents)
		})

		api.GET("/tickets", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			role, _ := claims["role"].(string)
			if role != "Admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			var tickets []Ticket
			if err := DB.Preload("Customer").Order("created_at desc").Find(&tickets).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_load_tickets"})
				return
			}

			c.JSON(http.StatusOK, tickets)
		})

		api.DELETE("/tickets", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			role, _ := claims["role"].(string)
			if role != "Admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}
			agentName, _ := claims["name"].(string)
			sub, _ := claims["sub"]
			var agentID uint
			switch v := sub.(type) {
			case float64:
				agentID = uint(v)
			case int64:
				agentID = uint(v)
			case uint:
				agentID = v
			default:
				agentID = 0
			}

			var tickets []Ticket
			if err := DB.Find(&tickets).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_load_tickets"})
				return
			}

			for _, t := range tickets {
				if t.AttachmentPath != "" {
					path := attachmentDiskPath(t.AttachmentPath)
					if path != "" {
						_ = os.Remove(path)
					}
				}
				DB.Unscoped().Where("ticket_id = ?", t.ID).Delete(&TicketReply{})
			}

			if err := DB.Unscoped().Where("1 = 1").Delete(&Ticket{}).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_delete_tickets"})
				return
			}
			logActivity(agentID, agentName, role, "DELETE_TICKET", fmt.Sprintf("ลบทิกเก็ตทั้งหมด %d รายการ", len(tickets)), c.ClientIP())

			c.Status(http.StatusNoContent)
		})

		api.GET("/customer/tickets", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			role, _ := claims["role"].(string)
			if role != "customer" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			sub, _ := claims["sub"]

			var customerID uint
			switch v := sub.(type) {
			case float64:
				customerID = uint(v)
			case int64:
				customerID = uint(v)
			case uint:
				customerID = v
			default:
				customerID = 0
			}

			if customerID == 0 {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			var tickets []Ticket
			if err := DB.Preload("Customer").Where("customer_id = ?", customerID).Order("created_at desc").Find(&tickets).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_load_tickets"})
				return
			}

			c.JSON(http.StatusOK, tickets)
		})

		api.DELETE("/customer/tickets/:id", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			role, _ := claims["role"].(string)
			if role != "customer" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}
			customerName, _ := claims["name"].(string)

			sub, _ := claims["sub"]

			var customerID uint
			switch v := sub.(type) {
			case float64:
				customerID = uint(v)
			case int64:
				customerID = uint(v)
			case uint:
				customerID = v
			default:
				customerID = 0
			}

			if customerID == 0 {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			id := c.Param("id")

			var ticket Ticket
			if err := DB.First(&ticket, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "ticket_not_found"})
				return
			}

			if ticket.CustomerID != customerID {
				c.JSON(http.StatusForbidden, gin.H{"error": "not_ticket_owner"})
				return
			}

			if ticket.AttachmentPath != "" {
				path := attachmentDiskPath(ticket.AttachmentPath)
				if path != "" {
					_ = os.Remove(path)
				}
			}

			DB.Unscoped().Where("ticket_id = ?", ticket.ID).Delete(&TicketReply{})

			if err := DB.Unscoped().Delete(&ticket).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_delete_ticket"})
				return
			}
			logActivity(customerID, customerName, role, "DELETE_TICKET", fmt.Sprintf("ลูกค้าลบทิกเก็ต #%d", ticket.ID), c.ClientIP())

			c.Status(http.StatusNoContent)
		})

		api.POST("/tickets", func(c *gin.Context) {
			title := c.PostForm("title")
			description := c.PostForm("description")
			priority := c.PostForm("priority")
			phone := c.PostForm("phone")

			if title == "" || description == "" || priority == "" || phone == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields"})
				return
			}

			customerID := uint(1)

			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				rawToken := strings.TrimPrefix(authHeader, "Bearer ")

				parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method")
					}
					return jwtSecret, nil
				})

				if err == nil && parsedToken.Valid {
					if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
						role, _ := claims["role"].(string)
						if role == "customer" {
							sub, _ := claims["sub"]
							switch v := sub.(type) {
							case float64:
								customerID = uint(v)
							case int64:
								customerID = uint(v)
							case uint:
								customerID = v
							}
						}
					}
				}
			}

			if !phoneRegex.MatchString(phone) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid phone number"})
				return
			}

			var attachmentPath string
			file, err := c.FormFile("attachment")
			if err == nil {
				filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(file.Filename))
				savePath := filepath.Join(uploadDir, filename)
				if err := c.SaveUploadedFile(file, savePath); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save attachment"})
					return
				}
				attachmentPath = "/uploads/" + filename
			}

			ticket := Ticket{
				Title:          title,
				Description:    description,
				Status:         "open",
				Priority:       priority,
				CustomerID:     customerID,
				AttachmentPath: attachmentPath,
				PhoneNumber:    phone,
			}

			if err := DB.Create(&ticket).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create ticket"})
				return
			}

			DB.Preload("Customer").First(&ticket, ticket.ID)

			logActivity(ticket.CustomerID, ticket.Customer.Name, "customer", "CREATE_TICKET", fmt.Sprintf("สร้างทิกเก็ต #%d: %s", ticket.ID, ticket.Title), c.ClientIP())

			c.JSON(http.StatusCreated, ticket)
		})

		api.GET("/tickets/:id/replies", func(c *gin.Context) {
			id := c.Param("id")

			var replies []TicketReply
			if err := DB.Where("ticket_id = ?", id).Order("created_at asc").Find(&replies).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_load_replies"})
				return
			}

			c.JSON(http.StatusOK, replies)
		})

		api.POST("/tickets/:id/replies", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			role, _ := claims["role"].(string)
			authorName, _ := claims["name"].(string)
			if (role != "Admin" && role != "customer") || authorName == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			message := ""
			var attachmentPath string
			contentType := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
			if strings.HasPrefix(contentType, "multipart/form-data") {
				message = strings.TrimSpace(c.PostForm("message"))
				file, err := c.FormFile("attachment")
				if err == nil && file != nil {
					ext := strings.ToLower(filepath.Ext(file.Filename))
					switch ext {
					case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico", ".tif", ".tiff", ".heic":
					default:
						c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_attachment_type"})
						return
					}
					filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(file.Filename))
					savePath := filepath.Join(uploadDir, filename)
					if err := c.SaveUploadedFile(file, savePath); err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_save_attachment"})
						return
					}
					attachmentPath = "/uploads/" + filename
				}
			} else {
				var payload struct {
					Message string `json:"message"`
				}
				if err := c.ShouldBindJSON(&payload); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_message"})
					return
				}
				message = strings.TrimSpace(payload.Message)
			}

			if message == "" && attachmentPath == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_message"})
				return
			}

			id := c.Param("id")

			var ticket Ticket
			if err := DB.First(&ticket, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "ticket_not_found"})
				return
			}

			if role == "customer" && strings.ToLower(ticket.Status) == "closed" {
				ticket.Status = "open"
				if err := DB.Save(&ticket).Error; err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_reopen_ticket"})
					return
				}
			}

			reply := TicketReply{
				TicketID:       ticket.ID,
				AuthorName:     authorName,
				AuthorRole:     role,
				Message:        message,
				AttachmentPath: attachmentPath,
			}

			if err := DB.Create(&reply).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_create_reply"})
				return
			}

			sub, _ := claims["sub"]
			var userID uint
			switch v := sub.(type) {
			case float64:
				userID = uint(v)
			case int64:
				userID = uint(v)
			case uint:
				userID = v
			}

			logActivity(userID, authorName, role, "REPLY_TICKET", fmt.Sprintf("ตอบกลับทิกเก็ต #%d", ticket.ID), c.ClientIP())

			c.JSON(http.StatusCreated, reply)
		})

		api.DELETE("/tickets/:id", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			role, _ := claims["role"].(string)
			if role != "Admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}
			agentName, _ := claims["name"].(string)
			sub, _ := claims["sub"]
			var agentID uint
			switch v := sub.(type) {
			case float64:
				agentID = uint(v)
			case int64:
				agentID = uint(v)
			case uint:
				agentID = v
			default:
				agentID = 0
			}

			id := c.Param("id")

			var ticket Ticket
			if err := DB.First(&ticket, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "ticket_not_found"})
				return
			}

			if ticket.AttachmentPath != "" {
				path := attachmentDiskPath(ticket.AttachmentPath)
				if path != "" {
					_ = os.Remove(path)
				}
			}

			DB.Unscoped().Where("ticket_id = ?", ticket.ID).Delete(&TicketReply{})

			if err := DB.Unscoped().Delete(&ticket).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_delete_ticket"})
				return
			}
			logActivity(agentID, agentName, role, "DELETE_TICKET", fmt.Sprintf("เจ้าหน้าที่ลบทิกเก็ต #%d", ticket.ID), c.ClientIP())

			c.Status(http.StatusNoContent)
		})

		api.PUT("/tickets/:id/assign", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			sub, _ := claims["sub"]
			role, _ := claims["role"].(string)
			agentName, _ := claims["name"].(string)
			if role != "Admin" || agentName == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			var agentID uint
			switch v := sub.(type) {
			case float64:
				agentID = uint(v)
			case int64:
				agentID = uint(v)
			case uint:
				agentID = v
			default:
				agentID = 0
			}

			id := c.Param("id")

			var ticket Ticket
			if err := DB.First(&ticket, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "ticket not found"})
				return
			}

			ticket.AssignedTo = agentName
			if agentID != 0 {
				ticket.AssignedUserID = &agentID
			}
			if ticket.Status == "open" {
				ticket.Status = "in_progress"
			}

			if err := DB.Save(&ticket).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update ticket"})
				return
			}

			DB.Preload("Customer").First(&ticket, ticket.ID)

			logActivity(agentID, agentName, role, "ASSIGN_TICKET", fmt.Sprintf("รับเคส #%d", ticket.ID), c.ClientIP())

			c.JSON(http.StatusOK, ticket)
		})

		api.PUT("/tickets/:id/release", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			sub, _ := claims["sub"]
			role, _ := claims["role"].(string)
			agentName, _ := claims["name"].(string)
			if role != "Admin" || agentName == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			var agentID uint
			switch v := sub.(type) {
			case float64:
				agentID = uint(v)
			case int64:
				agentID = uint(v)
			case uint:
				agentID = v
			default:
				agentID = 0
			}

			id := c.Param("id")

			var ticket Ticket
			if err := DB.First(&ticket, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "ticket not found"})
				return
			}

			if ticket.AssignedUserID == nil || agentID == 0 || *ticket.AssignedUserID != agentID {
				c.JSON(http.StatusForbidden, gin.H{"error": "not_ticket_owner"})
				return
			}

			ticket.AssignedTo = ""
			ticket.AssignedUserID = nil
			ticket.Status = "open"

			if err := DB.Save(&ticket).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update ticket"})
				return
			}

			DB.Preload("Customer").First(&ticket, ticket.ID)

			logActivity(agentID, agentName, role, "RELEASE_TICKET", fmt.Sprintf("Released Ticket #%d", ticket.ID), c.ClientIP())

			c.JSON(http.StatusOK, ticket)
		})

		api.PUT("/tickets/:id/complete", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			sub, _ := claims["sub"]
			role, _ := claims["role"].(string)
			agentName, _ := claims["name"].(string)
			if role != "Admin" || agentName == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			var agentID uint
			switch v := sub.(type) {
			case float64:
				agentID = uint(v)
			case int64:
				agentID = uint(v)
			case uint:
				agentID = v
			default:
				agentID = 0
			}

			if agentID == 0 {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			id := c.Param("id")

			var ticket Ticket
			if err := DB.First(&ticket, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "ticket_not_found"})
				return
			}

			if ticket.AssignedUserID == nil || *ticket.AssignedUserID != agentID {
				c.JSON(http.StatusForbidden, gin.H{"error": "not_ticket_owner"})
				return
			}

			if ticket.Status == "closed" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "ticket_already_closed"})
				return
			}

			var replyCount int64
			if err := DB.Model(&TicketReply{}).
				Where("ticket_id = ? AND author_role = ?", ticket.ID, "Admin").
				Count(&replyCount).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_check_replies"})
				return
			}

			if replyCount == 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "no_agent_reply_yet"})
				return
			}

			ticket.Status = "closed"

			if err := DB.Save(&ticket).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_update_ticket"})
				return
			}

			DB.Preload("Customer").First(&ticket, ticket.ID)

			logActivity(agentID, agentName, role, "COMPLETE_TICKET", fmt.Sprintf("ปิดงานทิกเก็ต #%d", ticket.ID), c.ClientIP())

			c.JSON(http.StatusOK, ticket)
		})

		api.GET("/admin/logs", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_or_invalid_token"})
				return
			}

			rawToken := strings.TrimPrefix(authHeader, "Bearer ")

			parsedToken, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtSecret, nil
			})
			if err != nil || !parsedToken.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
				return
			}

			role, _ := claims["role"].(string)
			if role != "Admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			var logs []ActivityLog
			if err := DB.Order("created_at desc").Limit(100).Find(&logs).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_load_logs"})
				return
			}

			c.JSON(http.StatusOK, logs)
		})
	}

	// Serve Frontend (Angular) for unknown routes
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		// Do not handle API routes or Uploads here
		if strings.HasPrefix(path, "/api") || strings.HasPrefix(path, "/uploads") {
			return
		}

		// Find dist folder
		distPath := "frontend/dist/ticket-frontend/browser" // Default for production
		if _, err := os.Stat(distPath); os.IsNotExist(err) {
			// Try parent directory (for local dev)
			if _, err := os.Stat("../" + distPath); err == nil {
				distPath = "../" + distPath
			} else {
				// Try legacy path
				legacyPath := "ticket-frontend/dist/ticket-frontend/browser"
				if _, err := os.Stat(legacyPath); err == nil {
					distPath = legacyPath
				}
			}
		}

		// Check if file exists in dist folder
		filePath := filepath.Join(distPath, path)
		if _, err := os.Stat(filePath); err == nil {
			c.File(filePath)
			return
		}

		// Fallback to index.html for SPA routes
		indexPath := filepath.Join(distPath, "index.html")
		c.File(indexPath)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
