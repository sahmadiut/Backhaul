package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func SendBinaryString(conn net.Conn, message string) error {
	// Header size
	const headerSize = 2

	// Create a buffer with the appropriate size for the message
	buf := make([]byte, headerSize+len(message))

	// Encode the length of the message as a big-endian 2-byte unsigned integer
	binary.BigEndian.PutUint16(buf[:headerSize], uint16(len(message)))

	// Copy the message into the buffer after the length
	copy(buf[headerSize:], message)

	// Send the buffer over the connection
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	// Successful
	return nil
}

func ReceiveBinaryString(conn net.Conn) (string, error) {
	// Header size
	const headerSize = 2

	// Create a buffer to read the first 2 bytes (the length of the message)
	lenBuf := make([]byte, headerSize)

	// Read exactly 2 bytes for the message length
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", fmt.Errorf("failed to read message length: %w", err)
	}

	// Decode the length of the message from the 2-byte buffer
	messageLength := binary.BigEndian.Uint16(lenBuf[:2])

	// Create a buffer of the appropriate size to hold the message
	messageBuf := make([]byte, messageLength)

	if _, err := io.ReadFull(conn, messageBuf); err != nil {
		return "", fmt.Errorf("failed to read message: %w", err)
	}

	// Convert the message buffer to a string and return it
	return string(messageBuf), nil
}

func SendBinaryTransportString(conn net.Conn, message string, transport byte) error {
	// Header size
	const headerSize = 3

	// Create a buffer with the appropriate size for the message
	buf := make([]byte, headerSize+len(message))

	// Encode the length of the message as a big-endian 2-byte unsigned integer
	binary.BigEndian.PutUint16(buf[:headerSize], uint16(len(message)))

	// encode the transport type
	buf[2] = transport

	// Copy the message into the buffer after the length
	copy(buf[headerSize:], message)

	// Send the buffer over the connection
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	// Successful
	return nil
}

func ReceiveBinaryTransportString(conn net.Conn) (string, byte, error) {
	// Header size
	const headerSize = 3

	// Create a buffer to read the first 3 bytes (2 for length + 1 for transport)
	lenBuf := make([]byte, headerSize)

	// Read exactly 3 bytes for the header
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", 0, fmt.Errorf("failed to read message header: %w", err)
	}

	// Decode the length of the message from the 2-byte buffer
	messageLength := binary.BigEndian.Uint16(lenBuf[:2])

	// decode the transport
	transport := lenBuf[2]

	// Create a buffer of the appropriate size to hold the message
	messageBuf := make([]byte, messageLength)

	if _, err := io.ReadFull(conn, messageBuf); err != nil {
		return "", 0, fmt.Errorf("failed to read message: %w", err)
	}

	// Convert the message buffer to a string and return it
	return string(messageBuf), transport, nil
}

// SendPort sends the port number as a 2-byte big-endian unsigned integer.
func SendBinaryInt(conn net.Conn, port uint16) error {
	// Create a 2-byte slice to hold the port number
	buf := make([]byte, 2)

	// Encode the port number as a big-endian 2-byte unsigned integer
	binary.BigEndian.PutUint16(buf, port)

	// Send the 2-byte buffer over the connection
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to send port number %d: %w", port, err)
	}

	// Successful
	return nil
}

// ReceivePort reads a 2-byte big-endian unsigned integer directly from the connection
func ReceiveBinaryInt(conn net.Conn) (uint16, error) {
	var port uint16

	// Use binary.Read to read the port directly from the connection
	err := binary.Read(conn, binary.BigEndian, &port)
	if err != nil {
		return 0, fmt.Errorf("failed to read port number from connection: %w", err)
	}

	// Successful
	return port, nil
}

func SendBinaryByte(conn net.Conn, message byte) error {
	// Create a 1-byte buffer and send the message
	messageBuf := [1]byte{message}

	if _, err := conn.Write(messageBuf[:]); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	// Successful
	return nil
}

func ReceiveBinaryByte(conn net.Conn) (byte, error) {
	var messageBuf [1]byte

	if _, err := io.ReadFull(conn, messageBuf[:]); err != nil {
		return 0, fmt.Errorf("failed to read message: %w", err)
	}

	return messageBuf[0], nil
}
