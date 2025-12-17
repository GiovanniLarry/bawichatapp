# Chat Application with Audio Support

A real-time chat application built with Node.js, Express, Socket.IO, and MongoDB that supports both text and audio messages with **end-to-end encryption**.

## Features

### End-to-End Encryption 🔒
- **AES-256 Encryption**: All text messages are encrypted using AES-256 encryption
- **Room-Specific Keys**: Each chat room has its own unique encryption key
- **Client-Side Encryption**: Messages are encrypted on the client before being sent to the server
- **Visual Indicators**: Lock icons show when encryption is enabled
- **Automatic Decryption**: Messages are automatically decrypted when received
- **Fallback Support**: Graceful handling of encryption/decryption failures

### Text Messages
- Real-time text messaging
- Message editing (within 5 minutes)
- Message deletion
- Read receipts
- Typing indicators
- **End-to-end encryption**

### Audio Messages
- **Audio Recording**: Click the microphone button to record audio messages
- **Audio Playback**: Play, pause, and seek through audio messages
- **Progress Bar**: Visual progress indicator for audio playback
- **Duration Display**: Shows audio duration in MM:SS format
- **Multiple Audio Support**: Only one audio can play at a time

### User Management
- User authentication
- Profile management
- User blocking and reporting
- Active users sidebar
- Online status indicators

## Encryption Implementation

### How It Works
1. **Key Generation**: Each chat room gets a unique 256-bit encryption key when created
2. **Client Encryption**: Text messages are encrypted on the client side using CryptoJS
3. **Secure Storage**: Only encrypted content is stored on the server
4. **Client Decryption**: Messages are decrypted on the client side when received
5. **Visual Feedback**: Lock icons indicate encrypted messages and rooms

### Security Features
- **AES-256**: Industry-standard encryption algorithm
- **Room Isolation**: Each room has its own encryption key
- **No Server Access**: Server cannot read encrypted message content
- **Key Management**: Encryption keys are stored securely with messages
- **Fallback Handling**: Graceful degradation if encryption fails

### Technical Details
- **Library**: CryptoJS for client-side encryption/decryption
- **Algorithm**: AES-256-CBC
- **Key Storage**: Encrypted with room metadata
- **Message Format**: Encrypted content stored separately from display content

## Audio Functionality Details

### Recording
- Uses the MediaRecorder API for browser-based audio recording
- Supports multiple audio formats (WebM, MP4, WAV, OGG)
- Automatic format detection based on browser support
- Recording timer with visual feedback
- Stop and cancel recording options

### Playback
- Custom audio player with play/pause controls
- Clickable progress bar for seeking
- Automatic stopping of other audio when new audio starts
- Visual feedback during playback

### File Management
- Audio files stored in `uploads/audio/` directory
- 10MB file size limit for audio uploads
- Automatic file naming with timestamps
- Duration metadata storage

## Technical Implementation

### Backend
- **Audio Upload Route**: `/api/upload-audio` for handling audio file uploads
- **Message Schema**: Extended to support audio messages with file metadata
- **Socket.IO Events**: Updated to handle audio message broadcasting
- **File Storage**: Multer configuration for audio file handling

### Frontend
- **MediaRecorder API**: Browser-based audio recording
- **Audio API**: HTML5 audio playback with custom controls
- **Real-time Updates**: Socket.IO for instant message delivery
- **Responsive Design**: Mobile-friendly audio controls

## Browser Support

### Audio Recording
- Chrome 47+
- Firefox 25+
- Safari 14.1+
- Edge 79+

### Audio Playback
- All modern browsers with HTML5 audio support

## Installation

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up MongoDB connection
4. Create environment variables (see `.env.example`)
5. Start the server: `npm start`

## Usage

1. Register/login to the application
2. Join or create a chat room
3. Use the microphone button to record audio messages
4. Click the play button on audio messages to listen
5. Use the progress bar to seek through audio

## File Structure

```
├── server.js              # Main server file with audio support
├── views/
│   └── chat.ejs          # Chat interface with audio controls
├── uploads/
│   └── audio/            # Audio file storage
└── package.json          # Dependencies
```

## API Endpoints

- `POST /api/upload-audio` - Upload audio files
- `GET /api/rooms/:roomId/messages` - Get room messages (including audio)
- Socket.IO events for real-time audio messaging

## Security Considerations

- File type validation for audio uploads
- File size limits (10MB for audio)
- User authentication required for uploads
- Secure file naming to prevent conflicts 