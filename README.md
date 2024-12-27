# AIRCBot: AI-powered IRC Bot with LLM Integration

AIRCBot is a Python-based IRC bot that interacts with a local language models to provide conversational AI capabilities. The bot is capable of joining an IRC channel, responding to direct messages, fetching the latest news, and managing authenticated user interactions. This document outlines how to install, configure, and use AIRCBot effectively with LMStudio locally, but you can modify this software to use external APIs too. 

---

## Features

### General
- Connects to IRC servers and channels.
- Supports basic IRC commands and responses.
- Authenticates users for private interactions.
- Maintains a conversation history to provide contextually aware responses.
- Supports automatic chat to queries
- Limited interaction with channel (if asked by user via UI)
- HAS Bugs. 

### AI-Powered Conversations
- Uses a locally hosted language model (via LMStudio API) to respond to messages.
- Can be adapted to use remote API (like OpenAI)
- Natural, context-aware language generation prompt, adapted for IRC interactions.
- Fetches and references the latest news for conversations about current events.

### Security
- Requires password-based authentication for private messaging.
- Implements basic anti-brute-force measures with temporary blocking for multiple failed login attempts.
- Uses a local LLM by default to increase privacy. 
- No secure connection support by now. 

### Graphical Interface
- Provides a Tkinter-based GUI for managing the bot.
- Features connection setup, message sending, and console logging.
- Includes a detailed help menu for user guidance.

![image](https://github.com/user-attachments/assets/67a12f4c-50e7-40c6-9e25-5511240a2652)
![image](https://github.com/user-attachments/assets/cb734374-d2f3-4259-af7a-8a989ddb4b2c)

---

## Requirements

### System Requirements
- Python 3.9 or later.
- Internet connection for IRC and RSS feed integration.
- LMStudio or equivalent local/remote language model API. Bot is configured to use LMStudio at `http://localhost:1234/v1/chat/completions`.
- Code is has comments to the lines you can customize, like defaults (nick, server, port), RSS feed address and API connection.

### Python Libraries
Ensure the following libraries are installed:
- `tkinter`
- `requests`
- `feedparser`
- `threading`
- `time`
- `hashlib`
- `irc` (irc.client)
  

Install missing dependencies using (example):
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
- **Server:** IRC server address (e.g., `open.ircnet.net`).
- **Port:** IRC server port (default: `6667`).
- **Nickname:** bot's IRC nickname (e.g., `Egidio`).
- **Channel:** IRC channel to join (e.g., `#example`).
- **Password:** Password required for private messaging authentication. Connection will not be possible if no password is set.

---

## Usage

Make sure your local LLM (eg. LMStudio) is up and running, then:

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
   - The bot fetches the latest news headlines and includes them in responses when relevant.

---

## Other Security Notes

### Authentication
- Users must authenticate with a password before initiating private conversations.
- After three failed attempts, users are temporarily blocked for 60 seconds.

### Logs
- All interactions and commands are logged in the console for transparency and debugging.

### Suggestions
- Do not leave the bot unattended, or in background, to avoid abuse.
- Removing the password protection from code is not a good idea, but you decide.
  
---

## Limitations

Some features are not supported to avoid complexity, and for security reasons:
- Supports only one channel at a time, to avoid excessive exposure.
- Does not handle CTCP (Client-To-Client Protocol) or DCC (Direct Client-to-Client) connections.
- Requires local hosting of the LMStudio model to increase privacy, but can be modified to use an external API.

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
   - If you modified the code to support external API, check if your endpoint and parameters are correct for your model.
   - If you modified the system prompt, try adapting it to get better answers.

---

## License

AIRCBot is open-source software. See the LICENSE file for details.

---

## Acknowledgments

- Built using Python and Tkinter.
- AI responses powered by LMStudio.
- Powered by Linux and Coffee.
- Inspired by cats. I love cats.

---

For questions, contributions, or feature requests, feel free to contact the project maintainer or open an issue in the repository.

