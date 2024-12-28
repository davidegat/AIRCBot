# AIRCBot: IRC Bot with local LLM Integration

No, not Discord: IRC. This is a generally useless project for a Python-based IRC bot that interacts with a local large language model, to provide conversational AI capabilities. The bot is able of joining an IRC channel, responding to direct messages, fetching the latest news, and managing authenticated user interactions. This document outlines how to install, configure, and use AIRCBot effectively with LMStudio (https://lmstudio.ai/) locally.

You can easily modify this software to use external APIs if needed (instructions in code comments).

---

## Features

### General
- Connects to IRC servers and channels.
- Supports IRC commands and responses.
- Authenticates users for private interactions.
- Maintains a conversation history to provide contextually aware responses.
- Features a personal conversation history for each user.
- Supports automatic chat to queries.
- Limited interaction with channel (if asked by user via UI, or if OP/VOICE status is given).

### AI-Powered Conversations
- Uses a locally hosted language model (via LMStudio API - download: https://lmstudio.ai/) to generate replies.
- Can be adapted to use remote API (like OpenAI - see comments in code for instructions).
- Natural, context-aware language generation prompt, adapted for IRC interactions.
- Fetches and references the latest news for conversations about current events.

### Graphical Interface
- Provides a Tkinter-based GUI for managing the bot and monitor its activity.
- Features connection setup, message and command sending, console logging.
- Includes help menu for user guidance.

![image](https://github.com/user-attachments/assets/384b1112-b769-4e05-92d0-8d642bfd3d80)
![image](https://github.com/user-attachments/assets/19530dc6-fd81-4e5f-b6f3-726a2fc4b0b2)

### Security
- Requires password-based authentication for private messaging.
- Implements basic anti-brute-force measures with temporary blocking for failed login attempts.
- Uses a local LLM setup by default to increase privacy. 
- Secure connection is supported by python irc libraries.
- Inputs/Outputs sanitized to avoid LLM to generate and send raw commands if prompted to do so.
- Implements ignore system for users tricking LLM into generating raw commands (ignore list resets when program restarts).

![image](https://github.com/user-attachments/assets/f21ea601-8cc8-4a9f-8d90-7084c0271f87)

---

## Requirements

### System Requirements
- Python 3.9 or later.
- Internet connection for IRC and RSS feed integration.
- LMStudio (https://lmstudio.ai/) or equivalent local language model API.
- Bot is configured to use LMStudio API at `http://localhost:1234/v1/chat/completions` endpoint. 
- If you can't run a local LLM model, follow instruction in the code comments to use your own external endpoint (like OpenAI API - Please refer to OpenAI documentation for API access). Less privacy is to be expected in this case.

### Python Libraries
Ensure the following libraries are installed and/or available:
- `tkinter`
- `requests`
- `feedparser`
- `threading`
- `time`
- `datetime`
- `hashlib`
- `irc` (irc.client)

If you plan to change the code to use external APIs, consider importing `openai`. Please refer to OpenAI documentation for API access, and code comments for instructions.

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
   Make sure your local LLM is up and running before connecting to IRC server, or you will only get a zombie bot parked on a channel.
   
---

## Configuration

### Connection Parameters
In the graphic interface, fill in the following fields:
- **Server:** IRC server address (e.g., `open.ircnet.net`).
- **Port:** IRC server port (default: `6667`).
- **Nickname:** bot's IRC nickname (e.g., `Egidio`).
- **Channel:** IRC channel to join (e.g., `#example`).
- **Password:** Password required for private messaging authentication. Connection will not be possible if no password is set.

---

## Usage

Make sure your local LLM is up and running, then:

1. **Connect the Bot:**
   Click the "Connect" button in the GUI.

2. **Join a Channel:**
   "Auto-Join" checkbox will ensure the bot will join channel upon connection, uncheck to get control over it.
   After connecting, click "Join Channel" to enter the specified IRC channel if Auto-Join is disabled.

4. **Send Messages:**
   - Use the message input field to send messages to default channel.
   - Use command input field to send IRC commands (e.g., `/who`, `/mode`).

5. **Private Messaging:**
   - Users can send direct messages to the bot.
   - The bot will request authentication if the user is not pre-authorized.
   - Once authenticated, user can interact with bot's AI brain and get responses.

6. **News Integration:**
   - The bot fetches latest news headlines and includes them in responses when and if relevant.

7. **Notes on LMStudio**
   - Tested with: Temp 0.55-0.65 / Response Lenght 100-150 / Context 2000tk
   - Similar results with different LLMs
   - Download https://lmstudio.ai/

---

## Other Security Notes or issues

- Multiple messages sent to the bot are queued. This must be handled in the future, to avoid overloads.
- Do not leave your bot unattended, or in background, to avoid abuse by users or breaking server ToS.
- Removing password protection from code seems not a good idea, but you decide.
- Conversation history is different from each user, anyways, do not discolse personal informations if using external APIs like OpenAI.
- Bot is not multiuser in a true sense. Only one password is allowed to be set, choose a **new one** before sharing it to other users. Do not reuse your own passwords.
  
---

## Other Limitations

Some features are not supported to avoid complexity, or for security reasons:
- Supports only one channel at a time, to avoid excessive exposure.
- Does not handle full CTCP (Client-To-Client Protocol) and does not handle DCC (Direct Client-to-Client) connections  at all.
- Requires local hosting of the LMStudio model to increase privacy, but can be modified to use an external API (see examples in code comments).

---

## Troubleshooting

1. **Connection Issues:**
   - Ensure server and port are correct.
   - Check your internet connection.
   - Check your firewall and/or vpn

2. **Authentication Fails:**
   - Verify correct password is entered.
   - Wait if temporarily blocked.
   - Hope if ignored for the session...

3. **AI Response Errors:**
   - Ensure LMStudio is running and accessible at `http://localhost:1234/v1/chat/completions`. A warning should be issued in the bot console if local API is unreachable.
      - NOTE: To use a different endpoint for local LLMs, just customize the LLM_ENDPOINT variable on top of the code.
   - If you modified the code to support external API, check if your endpoint and parameters are correct for your model.
   - If you modified the system prompt, try adapting it to get better answers.

4. **Strange(r) Things
   - Results depend upon which model you are usings, and relative settings.
   - Try using different models and settings for best results.
   - Keep values low: short response, short context, not too much temperature.

---

## License

AIRCBot is open-source software. See the LICENSE file for details.

---

## Acknowledgments

- Built using Python and Tkinter.
- AI responses by LMStudio.
- Powered by Linux and coffee.
- Cats. I love cats. And coffee.
- @lastknight (https://github.com/lastknight) who indirectly inspired it during a Christmas Night live of "Ciao Internet" :)
---

For questions, contributions, or feature requests, feel free to contact the project maintainer or open an issue in the repository. Software is provided as-is, by using it you accept to take all responsibility for any damage of any kind this software may cause to your data, device(s), firm, corporation, shop, family, friends, whole life, belongings, backyard, dignity and other moral and psycological stuff, your body or your cats'.

