package main

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name         string   `json:"name"`
	Email        string   `gorm:"unique" json:"email"`
	Role         string   `json:"role"`
	PasswordHash string   `json:"-"`
	Tickets      []Ticket `gorm:"foreignKey:CustomerID" json:"-"`
}

type Ticket struct {
	gorm.Model
	Title          string        `json:"title"`
	Description    string        `json:"description"`
	Status         string        `gorm:"index" json:"status"`
	Priority       string        `gorm:"index" json:"priority"`
	DueAt          *time.Time    `gorm:"index" json:"due_at,omitempty"`
	EscalationLevel int          `gorm:"index" json:"escalation_level"`
	LastEscalatedAt *time.Time   `gorm:"index" json:"last_escalated_at,omitempty"`
	Tags           string        `json:"tags"`
	CustomerID     uint          `gorm:"index" json:"customer_id"`
	Customer       User          `gorm:"foreignKey:CustomerID" json:"customer"`
	AttachmentPath string        `json:"attachment_path"`
	AttachmentThumbPath string   `json:"attachment_thumb_path"`
	Attachments    []TicketAttachment `gorm:"foreignKey:TicketID" json:"attachments,omitempty"`
	AssignedTo     string        `json:"assigned_to"`
	AssignedUserID *uint         `gorm:"index" json:"assigned_user_id"`
	AssignedUser   *User         `gorm:"foreignKey:AssignedUserID" json:"assigned_user,omitempty"`
	PhoneNumber    string        `json:"phone_number"`
	Replies        []TicketReply `gorm:"foreignKey:TicketID" json:"replies,omitempty"`
}

type TicketReply struct {
	gorm.Model
	TicketID        uint   `gorm:"index" json:"ticket_id"`
	Ticket         Ticket `gorm:"foreignKey:TicketID" json:"-"`
	AuthorName     string `json:"author_name"`
	AuthorRole     string `json:"author_role"`
	Message        string `json:"message"`
	AttachmentPath string `json:"attachment_path"`
	AttachmentThumbPath string `json:"attachment_thumb_path"`
	Attachments    []ReplyAttachment `gorm:"foreignKey:TicketReplyID" json:"attachments,omitempty"`
}

type ActivityLog struct {
	gorm.Model
	UserID    uint   `json:"user_id"`
	UserName  string `json:"user_name"`
	Role      string `json:"role"`
	Action    string `json:"action"`
	Details   string `json:"details"`
	IPAddress string `json:"ip_address"`
}

type TicketAttachment struct {
	gorm.Model
	TicketID  uint   `gorm:"index" json:"ticket_id"`
	Path      string `json:"path"`
	ThumbPath string `json:"thumb_path"`
}

type ReplyAttachment struct {
	gorm.Model
	TicketReplyID uint   `gorm:"index" json:"ticket_reply_id"`
	Path          string `json:"path"`
	ThumbPath     string `json:"thumb_path"`
}
