# AIRCBot: Advanced IRC Bot with LLM Integration

AIRCBot is a Python-based IRC bot that interacts with locally or remotely hosted language models to provide conversational AI capabilities. The bot is capable of joining an IRC channel, responding to direct messages, fetching the latest news, and managing authenticated user interactions. This document outlines how to install, configure, and use AIRCBot effectively with LMStudio locally.

---

## Features

### General
- Connects to IRC servers and channels.
- Supports basic IRC commands and responses.
- Authenticates users for private interactions.
- Maintains a conversation history to provide contextually aware responses.

### AI-Powered Conversations
- Uses a locally hosted language model (via LMStudio API) to respond to messages.
- Handles user queries with natural, context-aware language generation.
- Fetches and references the latest news from "Il Sole 24 Ore" RSS feed for conversations about current events.

### Security
- Requires password-based authentication for private messaging.
- Implements anti-brute-force measures with temporary blocking for multiple failed login attempts.

### Graphical Interface
- Provides a Tkinter-based GUI for managing the bot.
- Features connection setup, message sending, and console logging.
- Includes a detailed help menu for user guidance.

---

## Requirements

### System Requirements
- Python 3.9 or later.
- Internet connection for IRC and RSS feed integration.
- LMStudio or equivalent local language model API hosted at `http://localhost:1234/v1/chat/completions`.

### Python Libraries
Ensure the following libraries are installed:
- `tkinter`
- `requests`
- `feedparser`
- `socket`
- `threading`

Install missing dependencies using:
```bash
pip install requests feedparser
```

---

## Installation

1. **Clone the Repository:**
   Download the source code from the repository:
   ```bash
   git clone https://github.com/davidegat/AIRCBot.git
   cd aircbot
   ```

2. **Run the Script:**
   Execute the Python script using:
   ```bash
   python aircbot.py
   ```

---

## Configuration

### Connection Parameters
In the GUI, fill in the following fields:
- **Server:** The IRC server address (e.g., `open.ircnet.net`).
- **Port:** The IRC server port (default: `6667`).
- **Nickname:** The bot's IRC nickname (e.g., `Egidio`).
- **Channel:** The IRC channel to join (e.g., `#example`).
- **Password:** The password required for private messaging authentication.

### News Feed Integration
The bot fetches news from `https://www.ilsole24ore.com/rss/mondo.xml`. Ensure an active internet connection for this feature.

---

## Usage

1. **Start the Bot:**
   Launch the bot by running the script and clicking the "Connect" button in the GUI.

2. **Join a Channel:**
   After connecting, click "Join Channel" to enter the specified IRC channel.

3. **Send Messages:**
   - Use the message input field to send messages to the channel.
   - Use the command input field to send raw IRC commands (e.g., `/who`, `/mode`).

4. **Private Messaging:**
   - Users can send direct messages to the bot.
   - The bot will request authentication if the user is not pre-authorized.

5. **News Integration:**
   - The bot fetches the latest news headlines from "Il Sole 24 Ore" and includes them in responses when relevant.

---

## Security Features

### Authentication
- Users must authenticate with a password before initiating private conversations.
- After three failed attempts, users are temporarily blocked for 60 seconds.

### Logs
- All interactions and commands are logged in the console for transparency and debugging.

---

## Limitations

- Supports only one channel at a time.
- Does not handle CTCP (Client-To-Client Protocol) or DCC (Direct Client-to-Client).
- Requires local hosting of the LMStudio model.
- News feed updates are limited to the "Il Sole 24 Ore" RSS feed.

---

## Troubleshooting

1. **Connection Issues:**
   - Ensure the server and port are correct.
   - Check your internet connection.

2. **Authentication Fails:**
   - Verify the correct password is entered.
   - Wait 60 seconds if temporarily blocked.

3. **AI Response Errors:**
   - Ensure LMStudio is running and accessible at `http://localhost:1234/v1/chat/completions`.
   - Check the API response in the logs for troubleshooting.

4. **News Feed Issues:**
   - Verify the RSS feed URL is accessible.

---

## Customization

### Modify News Feed
To change the RSS feed source, update the `FEED_URL` in the `fetch_news_from_feed` function.

### Update Language Model
To use a different AI model or API, modify the `ask_gpt4` function to integrate with the desired endpoint.

### Add Features
The bot is modular, allowing for additional features such as multiple channel support, advanced user management, or enhanced AI capabilities.

---

## License

AIRCBot is open-source software licensed under the MIT License. See the LICENSE file for details.

---

## Acknowledgments

- Built using Python and Tkinter.
- AI responses powered by LMStudio.
- News integration from "Il Sole 24 Ore" RSS feed.
- Inspired by the flexibility and community of IRC networks.

---

For questions, contributions, or feature requests, feel free to contact the project maintainer or open an issue in the repository.

