// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	websocket "github.com/gorilla/websocket"
)

type XMLJSONNode = []interface{}

type WACallConfig struct {
	JID types.JID `json:"jid"`
	JIDNonAD types.JID `json:"jidNonAD"`
	PrivacyToken []int `json:"privacyToken"`
}

type WACallMessage struct {
	Type string `json:"type"`
	ID string `json:"ID"`
	EncJID string `json:"encJID"`
	Message interface{} `json:"message"`
}

type WACallResponse struct {
	Type string `json:"type"`
	Message interface{} `json:"message"`
}

var wsConnection *websocket.Conn
var wsLock sync.Mutex
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func handleWSEndpoint() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/ws", wsEndpoint)

	go func() {
		fmt.Println(http.ListenAndServe(":8082", nil))
	}()
}

func sendCallEventOnWSConnection(node *waBinary.Node, from types.JID, meta types.BasicCallMeta) {
	parsed := convertNodeToJSON(*node, from)

	wrappedPayload := WACallResponse{
		Type: "call",
		Message: map[string]interface{}{
			"call-meta": meta,
			"data": parsed,
		},
	}

	data, err := json.Marshal(wrappedPayload)
	if err != nil {
		fmt.Println(err)
	}

	if (wsConnection != nil) {
		wsLock.Lock()
		if err := wsConnection.WriteMessage(websocket.TextMessage, data); err != nil {
			fmt.Println(err)
		}
		wsLock.Unlock()
	}
}

func handleCallEvent(rawEvt interface{}) {
	switch evt := rawEvt.(type) {
	case *events.CallOffer:
		sendCallEventOnWSConnection(evt.Data, evt.BasicCallMeta.From, evt.BasicCallMeta)
	case *events.CallRelayLatency:
		sendCallEventOnWSConnection(evt.Data, evt.BasicCallMeta.From, evt.BasicCallMeta)
	case *events.CallPreAccept:
		sendCallEventOnWSConnection(evt.Data, evt.BasicCallMeta.From, evt.BasicCallMeta)
	case *events.CallAccept:
		sendCallEventOnWSConnection(evt.Data, evt.BasicCallMeta.From, evt.BasicCallMeta)
	case *events.CallTransport:
		sendCallEventOnWSConnection(evt.Data, evt.BasicCallMeta.From, evt.BasicCallMeta)
	case *events.CallTerminate:
		sendCallEventOnWSConnection(evt.Data, evt.BasicCallMeta.From, evt.BasicCallMeta)
	}
}

func convertJSONToNode(jsonNode interface{}, to types.JID, messageID types.MessageID) (waBinary.Node, bool) {
	casted, ok := jsonNode.(XMLJSONNode)
	if !ok {
		return waBinary.Node{}, false
	}

	attrs := waBinary.Attrs{}
	if casted[1] != nil {
		attrs = casted[1].(waBinary.Attrs)
		jidObj, ok := attrs["jid"].(map[string]interface{})
		if ok {
			if (jidObj["device"] == 0) {
				attrs["jid"] = fmt.Sprintf("%s@s.whatsapp.net", jidObj["user"])
				} else {
				attrs["jid"] = fmt.Sprintf("%s:%.0f@s.whatsapp.net", jidObj["user"], jidObj["device"])
			}
		}

		if (casted[0] == "call") {
			attrs["id"] = messageID
		}
	}

	if (casted[2] == nil) {
		return waBinary.Node{
			Tag: casted[0].(string),
			Attrs: attrs,
			Content: nil,
		}, false
	}

	content, ok := casted[2].(XMLJSONNode)
	if !ok {
		return waBinary.Node{}, false
	}

	// Content of the node is a byte array.
	_, ok = content[0].(float64)
	if ok {
		byteArray := make([]byte, len(content))

		for i, x := range content {
			b, ok := x.(float64)
			if ok {
				intValue, _ := strconv.Atoi(fmt.Sprintf("%.0f", b))
				byteArray[i] = byte(intValue)
			}
		}

		tag := casted[0].(string)

		if (tag == "enc") {
			encrypted, isPreKey, err := cli.DangerousInternals().
				EncryptMessageForDevice(byteArray, to, nil, nil)
			if err != nil {
				return waBinary.Node{}, false
			}

			return *encrypted, isPreKey
		}

		return waBinary.Node{
			Tag: tag,
			Attrs: attrs,
			Content: byteArray,
		}, false
	}

	// Content of the is a node array.
	_, ok = content[0].(XMLJSONNode)
	if ok {
		tag := casted[0].(string)
		newNodesLength := len(content)
		newNodes := make([]waBinary.Node, newNodesLength)

		if (tag == "to") {
			// Override recipient JID for separate devices for encrypting callKey.
			if attrJid, found := attrs["jid"].(string); found {
				to, _ = parseJID(attrJid)
			}
		}

		isPreKey := false

		for i, node := range content {
			res, isPreKeyTemp := convertJSONToNode(node, to, messageID)
			newNodes[i] = res
			isPreKey = isPreKey || isPreKeyTemp
		}

		if (tag == "offer" && isPreKey) {
			newNodes = append(newNodes,
				cli.DangerousInternals().MakeDeviceIdentityNode())
		}

		return waBinary.Node{
			Tag: tag,
			Attrs: attrs,
			Content: newNodes,
		}, isPreKey
	}

	// The content of the node is a single node.
	node, isPreKey := convertJSONToNode(content, to, messageID)

	return waBinary.Node{
		Tag: casted[0].(string),
		Attrs: attrs,
		Content: []waBinary.Node{node},
	}, isPreKey
}

func convertNodeToJSON(node waBinary.Node, from types.JID) interface{} {
	if (node.Tag == "enc") {
		decrypted, err := cli.DangerousInternals().DecryptDM(&node, from, false)
		if err == nil {
			// Trim first 4 bytes indicating callKey and unused last bytes after 36,
			// so the decrypted byte length is always 32 which is expected by wavoip.
			node.Content = decrypted[4:36]
		}
	}

	// The content of the node is a byte array.
	byteArray, ok := node.Content.([]byte)
	if ok {
		intArray := make([]int, len(byteArray))

		for i, x := range byteArray {
			intValue, _ := strconv.Atoi(fmt.Sprintf("%d", x))
			intArray[i] = intValue
		}

		return [...]interface{}{
			node.Tag,
			node.Attrs,
			intArray,
		}
	}

	// The content of the node are nodes.
	casted, ok := node.Content.([]waBinary.Node)
	if !ok {
		return [...]interface{}{
			node.Tag,
			node.Attrs,
			node.Content,
		}
	} else {
		parsedNodes := make([]interface{}, len(casted))
		for i, contentNode := range casted {
			parsedNode := convertNodeToJSON(contentNode, from)
			parsedNodes[i] = parsedNode
		}

		return [...]interface{}{
			node.Tag,
			node.Attrs,
			parsedNodes,
		}
	}
}

func handleMessage(msg string) []byte {
	var parsedMessage WACallMessage

	err := json.Unmarshal([]byte(msg), &parsedMessage)
	if err != nil {
		log.Errorf("Error parsing message: %v", err)
	}

	switch t := parsedMessage.Type; t {
	case "call":
		to := types.JID{}
		messageID := cli.GenerateMessageID()

		if (parsedMessage.EncJID != "") {
			to, _ = parseJID(parsedMessage.EncJID)
		}

		parsedNode, _ := convertJSONToNode(parsedMessage.Message, to, messageID)

		respChan := cli.DangerousInternals().WaitResponse(messageID)
		err = cli.DangerousInternals().SendNode(parsedNode)
		respNode := <-respChan

		responsePayload := WACallResponse{
			Type: "call",
			Message: convertNodeToJSON(*respNode, types.JID{}),
		}

		data, err := json.Marshal(responsePayload)
		if err != nil {
			fmt.Println(err)
		}

		return data
	case "devices-fetch":
		deviceIDs := []uint16{}
		jidToFetchDevicesFor, _ := parseJID(parsedMessage.ID)

		deviceJIDs, err := cli.GetUserDevices([]types.JID{jidToFetchDevicesFor})
		if err != nil {
			fmt.Println(err)
		}

		for _, deviceJID := range deviceJIDs {
			deviceIDs = append(deviceIDs, deviceJID.Device)
		}

		payload := WACallResponse{
			Type: "devices-fetch",
			Message: deviceIDs,
		}

		data, err := json.Marshal(payload)
		if err != nil {
			fmt.Println(err)
		}

		return data
	default:
		return []byte{}
	}
}

func reader(conn *websocket.Conn) {
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			fmt.Println(err)
			return
		}

		msg := string(p)

		go func() {
			recv := handleMessage(msg)

			wsLock.Lock()
			defer wsLock.Unlock()
			if err := conn.WriteMessage(messageType, recv); err != nil {
				fmt.Println(err)
				return
			}
		}()
	}
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Home Page")
}

func wsEndpoint(w http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println(err)
	}

	ownJID := cli.DangerousInternals().GetOwnID()

	privacyToken, err := cli.Store.PrivacyTokens.GetPrivacyToken(ownJID)
	if err != nil {
		fmt.Println(err)
	} else if privacyToken == nil {
		fmt.Println("ERROR: No privacy token for own user")
	}

	privacyTokenArray := make([]int, len(privacyToken.Token))

	for i, x := range privacyToken.Token {
		intValue, _ := strconv.Atoi(fmt.Sprintf("%d", x))
		privacyTokenArray[i] = intValue
	}

	ownConfig := WACallResponse{
		Type: "init",
		Message: WACallConfig{
			JID: ownJID,
			JIDNonAD: ownJID.ToNonAD(),
			PrivacyToken: privacyTokenArray,
		},
	}

	ownConfigData, _ := json.Marshal(ownConfig)
	fmt.Println("Client Connected", string(ownConfigData))

	err = ws.WriteMessage(1, ownConfigData)
	if err != nil {
			fmt.Println(err)
	}

	wsConnection = ws

	reader(ws)
}
