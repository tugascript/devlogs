package email

import (
	"net/smtp"
)

type Mail struct {
	auth    smtp.Auth
	port    string
	host    string
	address string
}

func NewMail(username, password, port, host, name string) *Mail {
	return &Mail{
		auth:    smtp.PlainAuth("", username, password, host),
		port:    port,
		host:    host,
		address: name + " <" + username + ">",
	}
}

func (m *Mail) SendMail(to string, subject, body string) error {
	addr := m.host + ":" + m.port
	msg := []byte("To: " + to + "\r\n" + "Subject: " + subject + "\r\n" + body)
	return smtp.SendMail(addr, m.auth, m.address, []string{to}, msg)
}
