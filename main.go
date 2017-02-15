package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
)

// getClient uses a Context and Config to retrieve a Token
// then generate a Client. It returns the generated Client.
func getClient(ctx context.Context, config *oauth2.Config) *http.Client {
	cacheFile, err := tokenCacheFile()
	if err != nil {
		log.Fatalf("Unable to get path to cached credential file. %v", err)
	}
	tok, err := tokenFromFile(cacheFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(cacheFile, tok)
	}
	return config.Client(ctx, tok)
}

// getTokenFromWeb uses Config to request a Token.
// It returns the retrieved Token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

// tokenCacheFile generates credential file path/filename.
// It returns the generated credential path/filename.
func tokenCacheFile() (string, error) {
	return "golang-gmail-api.json", nil
}

// tokenFromFile retrieves a Token from a given file path.
// It returns the retrieved Token and any read error encountered.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	t := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(t)
	defer f.Close()
	return t, err
}

// saveToken uses a file path to create a file and store the
// token in it.
func saveToken(file string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", file)
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

type Message struct {
	From      string
	To        string
	Subject   string
	BodyPlain string
	BodyHtml  string
}

func getMessagePartData(srv *gmail.Service, user, messageId string, messagePart *gmail.MessagePart) (string, error) {
	var dataBase64 string

	if messagePart.Body.AttachmentId != "" {
		body, err := srv.Users.Messages.Attachments.Get(user, messageId, messagePart.Body.AttachmentId).Do()
		if err != nil {
			return "", errors.Wrap(err, "getMessagePartData get attachment")
		}

		dataBase64 = body.Data
	} else {
		dataBase64 = messagePart.Body.Data
	}

	data, err := base64.URLEncoding.DecodeString(dataBase64)
	if err != nil {
		return "", errors.Wrap(err, "getMessagePartData base64 decode")
	}

	return string(data), nil
}

func findMessagePartByMimeType(messagePart *gmail.MessagePart, mimeType string) *gmail.MessagePart {
	if messagePart.MimeType == mimeType {
		return messagePart
	}
	if strings.HasPrefix(messagePart.MimeType, "multipart") {
		for _, part := range messagePart.Parts {
			if mp := findMessagePartByMimeType(part, mimeType); mp != nil {
				return mp
			}
		}
	}
	return nil
}

func findHeader(messagePart *gmail.MessagePart, name string) string {
	for _, header := range messagePart.Headers {
		if header.Name == name {
			return header.Value
		}
	}
	return ""
}

func parseMessage(srv *gmail.Service, gmailMessage *gmail.Message, user string) (*Message, error) {
	if gmailMessage.Payload == nil {
		return nil, fmt.Errorf("No payload in gmail message.")
	}

	message := &Message{
		From:    findHeader(gmailMessage.Payload, "From"),
		To:      findHeader(gmailMessage.Payload, "To"),
		Subject: findHeader(gmailMessage.Payload, "Subject"),
	}

	plainMessagePart := findMessagePartByMimeType(gmailMessage.Payload, "text/plain")
	if plainMessagePart != nil {
		plainMessage, err := getMessagePartData(srv, user, gmailMessage.Id, plainMessagePart)
		if err != nil {
			return nil, errors.Wrap(err, "parseMessage plain")
		}
		message.BodyPlain = plainMessage
	}

	htmlMessagePart := findMessagePartByMimeType(gmailMessage.Payload, "text/html")
	if htmlMessagePart != nil {
		htmlMessage, err := getMessagePartData(srv, user, gmailMessage.Id, htmlMessagePart)
		if err != nil {
			return nil, errors.Wrap(err, "parseMessage html")
		}
		message.BodyHtml = htmlMessage
	}

	return message, nil
}

func marshalResponse(response *Message, msgId string) (*gmail.Message, error) {
	template := `From: %s
To: %s
Subject: %s
References: %s
In-Reply-To: %s

%s`

	populated := fmt.Sprintf(
		template,
		response.From,
		response.To,
		response.Subject,
		msgId,
		msgId,
		response.BodyPlain,
	)

	gmailResponse := &gmail.Message{
		Raw: base64.URLEncoding.EncodeToString([]byte(populated)),
	}

	return gmailResponse, nil
}

func main() {
	ctx := context.Background()

	b, err := ioutil.ReadFile("client_secret.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved credentials
	// at ~/.credentials/gmail-go-quickstart.json
	config, err := google.ConfigFromJSON(b, gmail.GmailReadonlyScope, gmail.GmailModifyScope, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(ctx, config)

	srv, err := gmail.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve gmail Client %v", err)
	}

	user := "me"
	response, err := srv.Users.Messages.List(user).Q("is:unread").Do()
	if err != nil {
		log.Fatalf("Unable to retrieve messages: %v", err)
	}
	if len(response.Messages) > 0 {
		for _, message := range response.Messages {
			gmailMsg, err := srv.Users.Messages.Get(user, message.Id).Do()
			if err != nil {
				log.Fatalf("Unable to retrieve message: %v", err)
			}

			msg, err := parseMessage(srv, gmailMsg, user)
			if err != nil {
				log.Fatalf("Unable to parse message: %v", err)
			}

			response, err := processMessage(msg)
			if err != nil {
				log.Fatalf("Unable to process message: %v", err)
			}

			if response.To == "" {
				response.To = msg.From
			}
			if response.From == "" {
				response.From = msg.To
			}
			if response.Subject == "" {
				response.Subject = msg.Subject
			}

			msgId := findHeader(gmailMsg.Payload, "Message-ID")
			gmailResponse, err := marshalResponse(response, msgId)
			if err != nil {
				log.Fatalf("Unable to marshal response: %v", err)
			}

			_, err = srv.Users.Messages.Send(user, gmailResponse).Do()
			if err != nil {
				log.Fatalf("Unable to send response: %v", err)
			}

			_, err = srv.Users.Messages.Modify(user, message.Id, &gmail.ModifyMessageRequest{
				RemoveLabelIds: []string{"UNREAD"},
			}).Do()
			if err != nil {
				log.Fatalf("Unable to mark message as read: %v", err)
			}
		}
	}
}

func processMessage(msg *Message) (*Message, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, errors.Wrap(err, "processMessage")
	}

	response := &Message{
		BodyPlain: string(body),
	}

	return response, nil
}
