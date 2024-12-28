# AIRCBot: AI-powered IRC Bot with local LLM Integration

AIRCBot is a Python-based IRC bot that interacts with a local language models to provide conversational AI capabilities. The bot is capable of joining an IRC channel, responding to direct messages, fetching the latest news, and managing authenticated user interactions. This document outlines how to install, configure, and use AIRCBot effectively with LMStudio (https://lmstudio.ai/) locally.

You can easily modify this software to use external APIs, if needed. 

---

## Features

### General
- Connects to IRC servers and channels.
- Supports IRC commands and responses.
- Authenticates users for private interactions.
- Maintains a conversation history to provide contextually aware responses.
- Supports automatic chat to queries.
- Limited interaction with channel (if asked by user via UI, or if OP status is given).

### AI-Powered Conversations
- Uses a locally hosted language model (via LMStudio API - download: https://lmstudio.ai/) to respond to messages.
- Can be adapted to use remote API (like OpenAI).
- Natural, context-aware language generation prompt, adapted for IRC interactions.
- Fetches and references the latest news for conversations about current events.

### Graphical Interface
- Provides a Tkinter-based GUI for managing the bot.
- Features connection setup, message sending, and console logging.
- Includes help menu for user guidance.

![image](https://github.com/user-attachments/assets/384b1112-b769-4e05-92d0-8d642bfd3d80)
![image](https://github.com/user-attachments/assets/19530dc6-fd81-4e5f-b6f3-726a2fc4b0b2)

### Security
- Requires password-based authentication for private messaging.
- Implements basic anti-brute-force measures with temporary blocking for failed login attempts.
- Uses a local LLM by default to increase privacy. 
- Secure connection support.
- Sanitized to avoid LLM to send raw commands to The IRC server if prompted to do so.
- Implements ignore system for users tricking LLM into generating raw commands.

![image](https://github.com/user-attachments/assets/f21ea601-8cc8-4a9f-8d90-7084c0271f87)

---

## Requirements

### System Requirements
- Python 3.9 or later.
- Internet connection for IRC and RSS feed integration.
- LMStudio (https://lmstudio.ai/) or equivalent local language model API.
- Bot is configured to use LMStudio API at `http://localhost:1234/v1/chat/completions` endpoint.
- If you can't run a local LLM model, follow comments in the code to use your own external endpoint (like OpenAI API - Please refer to OpenAI documentation for API access).

### Python Libraries
Ensure the following libraries are installed and available:
- `tkinter`
- `requests`
- `feedparser`
- `threading`
- `time`
- `datetime`
- `hashlib`
- `irc` (irc.client)

If you plan to change the code, consider also `openai`. Please refer to OpenAI documentation for API access.

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
3. **LLM (LMStudio)**
   Make sure your local LLM is up and running before connecting to IRC server.
   
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

Make sure your local LLM is up and running, then:

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

6. **Notes on LMStudio**
   - Tested with: Temp 0.55-0.65 / Response Lenght 100-150 / Context 2000tk
   - Similar results with different LLMs
   - Download https://lmstudio.ai/

---

## Other Security Notes

### Authentication
- Users must authenticate with a password before initiating private conversations.
- After three failed attempts, users are temporarily blocked for 60 seconds.
- Multiple messages are queued (this must be handled in the future, to avoid overload).

### Logs
- All interactions and commands are logged in the console for transparency and debugging.

### Suggestions
- Do not leave the bot unattended, or in background, to avoid abuse.
- Removing password protection from code seems not a good idea, but you decide.
  
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
   - Wait if temporarily blocked.

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

