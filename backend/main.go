package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/image/draw"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB
var phoneRegex = regexp.MustCompile(`^0\d{8,10}$`)
var jwtSecret = []byte("change-this-secret-in-production")
var uploadDir = "uploads"

type objectStorage struct {
	client        *minio.Client
	bucket        string
	publicBaseURL string
}

var store *objectStorage

func normalizeBaseURL(raw string) string {
	u := strings.TrimSpace(raw)
	u = strings.TrimRight(u, "/")
	return u
}

func initObjectStorage() (*objectStorage, error) {
	endpoint := strings.TrimSpace(os.Getenv("S3_ENDPOINT"))
	bucket := strings.TrimSpace(os.Getenv("S3_BUCKET"))
	accessKey := strings.TrimSpace(os.Getenv("S3_ACCESS_KEY"))
	secretKey := strings.TrimSpace(os.Getenv("S3_SECRET_KEY"))
	region := strings.TrimSpace(os.Getenv("S3_REGION"))
	publicBase := normalizeBaseURL(os.Getenv("S3_PUBLIC_BASE_URL"))
	forcePathStyle := strings.EqualFold(strings.TrimSpace(os.Getenv("S3_FORCE_PATH_STYLE")), "true")

	if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
		return nil, nil
	}

	secure := true
	if u, err := url.Parse(endpoint); err == nil && u.Scheme != "" {
		secure = strings.EqualFold(u.Scheme, "https")
		endpoint = u.Host
	} else {
		secure = strings.EqualFold(strings.TrimSpace(os.Getenv("S3_USE_SSL")), "true")
	}

	opts := &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: secure,
		Region: region,
	}
	if forcePathStyle {
		opts.BucketLookup = minio.BucketLookupPath
	}

	client, err := minio.New(endpoint, opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: region}); err != nil {
			return nil, err
		}
	}

	if publicBase == "" {
		scheme := "https"
		if !secure {
			scheme = "http"
		}
		publicBase = normalizeBaseURL(fmt.Sprintf("%s://%s/%s", scheme, endpoint, bucket))
	}

	return &objectStorage{client: client, bucket: bucket, publicBaseURL: publicBase}, nil
}

func (s *objectStorage) publicURL(key string) string {
	if s == nil {
		return ""
	}
	key = strings.TrimPrefix(key, "/")
	return s.publicBaseURL + "/" + key
}

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
		renderFlag := strings.EqualFold(strings.TrimSpace(os.Getenv("RENDER")), "true")
		if renderFlag {
			return "/var/data/uploads"
		}
		if info, err := os.Stat("/var/data"); err == nil && info.IsDir() {
			candidate := "/var/data/uploads"
			if err := os.MkdirAll(candidate, os.ModePerm); err == nil {
				return candidate
			}
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

func deleteAttachmentPath(path string) {
	raw := strings.TrimSpace(path)
	if raw == "" {
		return
	}
	if store != nil && store.client != nil {
		prefix := store.publicBaseURL + "/"
		if strings.HasPrefix(raw, prefix) {
			key := strings.TrimPrefix(raw, prefix)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = store.client.RemoveObject(ctx, store.bucket, key, minio.RemoveObjectOptions{})
			return
		}
	}
	if disk := attachmentDiskPath(raw); disk != "" {
		_ = os.Remove(disk)
	}
}

func isAllowedImageExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico", ".tif", ".tiff", ".heic":
		return true
	default:
		return false
	}
}

func safeUploadName(original string) string {
	base := filepath.Base(strings.TrimSpace(original))
	if base == "" || base == "." {
		return "file"
	}
	base = strings.ReplaceAll(base, "\\", "_")
	base = strings.ReplaceAll(base, "/", "_")
	return base
}

func normalizeTags(tags []string) string {
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		n := strings.ToLower(strings.TrimSpace(t))
		if n == "" {
			continue
		}
		if len(n) > 40 {
			n = n[:40]
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return strings.Join(out, ",")
}

func slackWebhookURL() string {
	return strings.TrimSpace(os.Getenv("SLACK_WEBHOOK_URL"))
}

func postSlackMessage(text string) error {
	webhook := slackWebhookURL()
	if webhook == "" {
		return nil
	}
	payload := map[string]string{"text": text}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack_status_%d", resp.StatusCode)
	}
	return nil
}

func buildDailyDigest(now time.Time) (string, error) {
	var openCount int64
	if err := DB.Model(&Ticket{}).Where("status <> ?", "closed").Count(&openCount).Error; err != nil {
		return "", err
	}
	var overdueCount int64
	if err := DB.Model(&Ticket{}).Where("status <> ? AND due_at IS NOT NULL AND due_at < ?", "closed", now).Count(&overdueCount).Error; err != nil {
		return "", err
	}
	soon := now.Add(24 * time.Hour)
	var dueSoonCount int64
	if err := DB.Model(&Ticket{}).Where("status <> ? AND due_at IS NOT NULL AND due_at >= ? AND due_at <= ?", "closed", now, soon).Count(&dueSoonCount).Error; err != nil {
		return "", err
	}
	var newest []Ticket
	if err := DB.Order("created_at desc").Limit(5).Find(&newest).Error; err != nil {
		return "", err
	}

	lines := []string{
		fmt.Sprintf("Daily Digest (%s)", now.Format("2006-01-02")),
		fmt.Sprintf("Open: %d | Overdue: %d | Due<24h: %d", openCount, overdueCount, dueSoonCount),
	}
	for _, t := range newest {
		lines = append(lines, fmt.Sprintf("#%d [%s] %s", t.ID, t.Status, t.Title))
	}
	return strings.Join(lines, "\n"), nil
}

func runDailyDigestLoop() {
	enable := strings.EqualFold(strings.TrimSpace(os.Getenv("DIGEST_ENABLED")), "true") || slackWebhookURL() != ""
	if !enable {
		return
	}
	hour := 9
	if v := strings.TrimSpace(os.Getenv("DIGEST_HOUR")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 23 {
			hour = n
		}
	}
	var lastSent string
	ticker := time.NewTicker(15 * time.Minute)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			if now.Hour() != hour || now.Minute() > 14 {
				continue
			}
			day := now.Format("2006-01-02")
			if lastSent == day {
				continue
			}
			msg, err := buildDailyDigest(now)
			if err == nil {
				_ = postSlackMessage(msg)
				lastSent = day
			}
		}
	}()
}

func escalateOverdueOnce(now time.Time) ([]Ticket, error) {
	var tickets []Ticket
	cutoff := now.Add(-12 * time.Hour)
	if err := DB.Where("status <> ? AND due_at IS NOT NULL AND due_at < ? AND (last_escalated_at IS NULL OR last_escalated_at < ?)", "closed", now, cutoff).
		Order("due_at asc").
		Limit(50).
		Find(&tickets).Error; err != nil {
		return nil, err
	}
	if len(tickets) == 0 {
		return tickets, nil
	}
	for _, t := range tickets {
		level := t.EscalationLevel + 1
		t.EscalationLevel = level
		t.LastEscalatedAt = &now
		t.Priority = "High"
		if err := DB.Save(&t).Error; err != nil {
			return nil, err
		}
		logActivity(0, "system", "system", "ESCALATE_TICKET", fmt.Sprintf("Escalate ticket #%d level=%d", t.ID, level), "")
	}
	return tickets, nil
}

func runEscalationLoop() {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("ESCALATION_ENABLED")), "false") {
		return
	}
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			tickets, err := escalateOverdueOnce(now)
			if err != nil || len(tickets) == 0 {
				continue
			}
			lines := []string{fmt.Sprintf("Escalation: %d ticket(s) overdue", len(tickets))}
			for _, t := range tickets {
				due := ""
				if t.DueAt != nil {
					due = t.DueAt.Format(time.RFC3339)
				}
				lines = append(lines, fmt.Sprintf("#%d level=%d due=%s %s", t.ID, t.EscalationLevel, due, t.Title))
			}
			_ = postSlackMessage(strings.Join(lines, "\n"))
		}
	}()
}

func makeThumb(img image.Image, maxDim int) image.Image {
	b := img.Bounds()
	w := b.Dx()
	h := b.Dy()
	if w <= 0 || h <= 0 {
		return img
	}
	scaleW := maxDim
	scaleH := int(float64(h) * float64(maxDim) / float64(w))
	if h > w {
		scaleH = maxDim
		scaleW = int(float64(w) * float64(maxDim) / float64(h))
	}
	if scaleW < 1 {
		scaleW = 1
	}
	if scaleH < 1 {
		scaleH = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, scaleW, scaleH))
	draw.ApproxBiLinear.Scale(dst, dst.Bounds(), img, b, draw.Over, nil)
	return dst
}

func thumbnailJPEG(fileReader io.Reader) ([]byte, error) {
	img, _, err := image.Decode(fileReader)
	if err != nil {
		return nil, err
	}
	thumb := makeThumb(img, 360)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, thumb, &jpeg.Options{Quality: 80}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func inferContentType(fileName string, headerContentType string) string {
	ct := strings.TrimSpace(headerContentType)
	if ct != "" {
		return ct
	}
	ext := strings.ToLower(filepath.Ext(fileName))
	if ext != "" {
		if v := mime.TypeByExtension(ext); v != "" {
			return v
		}
	}
	return "application/octet-stream"
}

func storeAttachment(c *gin.Context, fileHeader *multipart.FileHeader) (string, string, error) {
	if fileHeader == nil {
		return "", "", nil
	}

	originalName := safeUploadName(fileHeader.Filename)
	ext := strings.ToLower(filepath.Ext(originalName))
	now := time.Now()
	uniqueName := fmt.Sprintf("%d_%s", now.UnixNano(), originalName)
	contentType := inferContentType(uniqueName, fileHeader.Header.Get("Content-Type"))
	tryThumb := strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "image/") || isAllowedImageExt(ext)
	if fileHeader.Size > 25*1024*1024 {
		tryThumb = false
	}

	if store != nil && store.client != nil {
		key := fmt.Sprintf("attachments/%04d/%02d/%s", now.Year(), int(now.Month()), uniqueName)
		ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
		defer cancel()

		f, err := fileHeader.Open()
		if err != nil {
			return "", "", err
		}
		defer f.Close()

		if _, err := store.client.PutObject(ctx, store.bucket, key, f, fileHeader.Size, minio.PutObjectOptions{
			ContentType: contentType,
		}); err != nil {
			return "", "", err
		}

		thumbURL := ""
		if tryThumb {
			tf, err := fileHeader.Open()
			if err == nil {
				defer tf.Close()
				if thumbBytes, err := thumbnailJPEG(tf); err == nil && len(thumbBytes) > 0 {
					thumbName := strings.TrimSuffix(uniqueName, ext) + ".jpg"
					thumbKey := fmt.Sprintf("thumbnails/%04d/%02d/%s", now.Year(), int(now.Month()), thumbName)
					tr := bytes.NewReader(thumbBytes)
					_, upErr := store.client.PutObject(ctx, store.bucket, thumbKey, tr, int64(len(thumbBytes)), minio.PutObjectOptions{
						ContentType: "image/jpeg",
					})
					if upErr == nil {
						thumbURL = store.publicURL(thumbKey)
					}
				}
			}
		}
		return store.publicURL(key), thumbURL, nil
	}

	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		return "", "", err
	}

	savePath := filepath.Join(uploadDir, uniqueName)
	if err := c.SaveUploadedFile(fileHeader, savePath); err != nil {
		return "", "", err
	}

	thumbURL := ""
	thumbDir := filepath.Join(uploadDir, "thumbs")
	if tryThumb {
		if err := os.MkdirAll(thumbDir, os.ModePerm); err == nil {
			if f, err := os.Open(savePath); err == nil {
				defer f.Close()
				if thumbBytes, err := thumbnailJPEG(f); err == nil && len(thumbBytes) > 0 {
					thumbName := strings.TrimSuffix(uniqueName, ext) + ".jpg"
					thumbPath := filepath.Join(thumbDir, thumbName)
					_ = os.WriteFile(thumbPath, thumbBytes, 0644)
					thumbURL = "/uploads/thumbs/" + thumbName
				}
			}
		}
	}

	return "/uploads/" + uniqueName, thumbURL, nil
}

func main() {
	ConnectDatabase()
	r := gin.Default()
	r.Use(gzip.Gzip(gzip.DefaultCompression))
	uploadDir = resolveUploadDir()
	s, err := initObjectStorage()
	if err != nil {
		log.Fatal("Failed to init object storage", err)
	}
	store = s

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
				deleteAttachmentPath(t.AttachmentPath)
				deleteAttachmentPath(t.AttachmentThumbPath)
				var replies []TicketReply
				_ = DB.Where("ticket_id = ?", t.ID).Find(&replies).Error
				for _, r := range replies {
					deleteAttachmentPath(r.AttachmentPath)
					deleteAttachmentPath(r.AttachmentThumbPath)
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

			deleteAttachmentPath(ticket.AttachmentPath)
			deleteAttachmentPath(ticket.AttachmentThumbPath)
			var replies []TicketReply
			_ = DB.Where("ticket_id = ?", ticket.ID).Find(&replies).Error
			for _, r := range replies {
				deleteAttachmentPath(r.AttachmentPath)
				deleteAttachmentPath(r.AttachmentThumbPath)
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
			var attachmentThumbPath string
			file, err := c.FormFile("attachment")
			if err == nil && file != nil {
				path, thumb, err := storeAttachment(c, file)
				if err != nil {
					if err.Error() == "invalid_attachment_type" {
						c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_attachment_type"})
						return
					}
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_save_attachment"})
					return
				}
				attachmentPath = path
				attachmentThumbPath = thumb
			}

			ticket := Ticket{
				Title:               title,
				Description:         description,
				Status:              "open",
				Priority:            priority,
				CustomerID:          customerID,
				AttachmentPath:      attachmentPath,
				AttachmentThumbPath: attachmentThumbPath,
				PhoneNumber:         phone,
			}
			switch strings.ToLower(strings.TrimSpace(priority)) {
			case "high", "สูง":
				d := time.Now().Add(24 * time.Hour)
				ticket.DueAt = &d
			case "medium", "ปานกลาง":
				d := time.Now().Add(48 * time.Hour)
				ticket.DueAt = &d
			default:
				d := time.Now().Add(72 * time.Hour)
				ticket.DueAt = &d
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
			var attachmentThumbPath string
			contentType := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Type")))
			if strings.HasPrefix(contentType, "multipart/form-data") {
				message = strings.TrimSpace(c.PostForm("message"))
				file, err := c.FormFile("attachment")
				if err == nil && file != nil {
					path, thumb, err := storeAttachment(c, file)
					if err != nil {
						if err.Error() == "invalid_attachment_type" {
							c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_attachment_type"})
							return
						}
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_save_attachment"})
						return
					}
					attachmentPath = path
					attachmentThumbPath = thumb
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
				TicketID:            ticket.ID,
				AuthorName:          authorName,
				AuthorRole:          role,
				Message:             message,
				AttachmentPath:      attachmentPath,
				AttachmentThumbPath: attachmentThumbPath,
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

			deleteAttachmentPath(ticket.AttachmentPath)
			deleteAttachmentPath(ticket.AttachmentThumbPath)
			var replies []TicketReply
			_ = DB.Where("ticket_id = ?", ticket.ID).Find(&replies).Error
			for _, r := range replies {
				deleteAttachmentPath(r.AttachmentPath)
				deleteAttachmentPath(r.AttachmentThumbPath)
			}

			DB.Unscoped().Where("ticket_id = ?", ticket.ID).Delete(&TicketReply{})

			if err := DB.Unscoped().Delete(&ticket).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_delete_ticket"})
				return
			}
			logActivity(agentID, agentName, role, "DELETE_TICKET", fmt.Sprintf("เจ้าหน้าที่ลบทิกเก็ต #%d", ticket.ID), c.ClientIP())

			c.Status(http.StatusNoContent)
		})

		api.PUT("/tickets/:id/tags", func(c *gin.Context) {
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

			var payload struct {
				Tags []string `json:"tags"`
			}
			if err := c.ShouldBindJSON(&payload); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
				return
			}

			id := c.Param("id")
			var ticket Ticket
			if err := DB.First(&ticket, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "ticket_not_found"})
				return
			}

			ticket.Tags = normalizeTags(payload.Tags)
			if err := DB.Save(&ticket).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_update_ticket"})
				return
			}
			c.JSON(http.StatusOK, ticket)
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

		api.GET("/admin/digest/preview", func(c *gin.Context) {
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

			text, err := buildDailyDigest(time.Now())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_build_digest"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"text": text})
		})

		api.POST("/admin/digest/send", func(c *gin.Context) {
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
			name, _ := claims["name"].(string)
			if role != "Admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			text, err := buildDailyDigest(time.Now())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_build_digest"})
				return
			}
			if err := postSlackMessage(text); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_send_digest"})
				return
			}
			logActivity(0, name, role, "SEND_DAILY_DIGEST", "Manual send", c.ClientIP())
			c.JSON(http.StatusOK, gin.H{"sent": true, "text": text})
		})

		api.POST("/admin/escalate/run", func(c *gin.Context) {
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
			name, _ := claims["name"].(string)
			if role != "Admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
				return
			}

			tickets, err := escalateOverdueOnce(time.Now())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_escalate"})
				return
			}
			logActivity(0, name, role, "RUN_ESCALATION", fmt.Sprintf("count=%d", len(tickets)), c.ClientIP())
			c.JSON(http.StatusOK, gin.H{"count": len(tickets), "tickets": tickets})
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

	runDailyDigestLoop()
	runEscalationLoop()

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
