package main

import (
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
	Status         string        `json:"status"`
	Priority       string        `json:"priority"`
	CustomerID     uint          `json:"customer_id"`
	Customer       User          `gorm:"foreignKey:CustomerID" json:"customer"`
	AttachmentPath string        `json:"attachment_path"`
	AssignedTo     string        `json:"assigned_to"`
	AssignedUserID *uint         `json:"assigned_user_id"`
	AssignedUser   *User         `gorm:"foreignKey:AssignedUserID" json:"assigned_user,omitempty"`
	PhoneNumber    string        `json:"phone_number"`
	Replies        []TicketReply `gorm:"foreignKey:TicketID" json:"replies,omitempty"`
}

type TicketReply struct {
	gorm.Model
	TicketID   uint   `json:"ticket_id"`
	Ticket     Ticket `gorm:"foreignKey:TicketID" json:"-"`
	AuthorName string `json:"author_name"`
	AuthorRole string `json:"author_role"`
	Message    string `json:"message"`
}
