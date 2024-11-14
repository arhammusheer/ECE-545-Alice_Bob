#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>
#include <Arduino.h>

// Configuration constants and enumerations
#define SCREEN_WIDTH 128   // OLED display width, in pixels
#define SCREEN_HEIGHT 128  // OLED display height, in pixels
#define OLED_RESET -1      // Can set an oled reset pin if desired
#define OLED_CS 5          // Chip Select
#define OLED_DC 6          // Data/Command

#define MODE_SELECT 12  // Mode select pin (pull down)
#define IS_ALICE 13     // Alice/Bob mode select pin (pull down)

const int lineHeight = 8;                         // Height of each line in pixels
const int maxLines = SCREEN_HEIGHT / lineHeight;  // Maximum number of lines on the display

const unsigned long sendInterval = 5000;  // Interval in milliseconds between sends (5 seconds)

enum SecurityLevel {
  LEVEL0,
  LEVEL1,
  LEVEL2
};

// Utility function for modular exponentiation
long modExp(long base, long exponent, long modulus) {
  long result = 1;
  base = base % modulus;
  while (exponent > 0) {
    if (exponent % 2 == 1) {  // If exponent is odd
      result = (result * base) % modulus;
    }
    exponent = exponent >> 1;    // exponent = exponent / 2
    base = (base * base) % modulus;
  }
  return result;
}

// DisplayManager class handles all display-related functionalities
class DisplayManager {
public:
  DisplayManager()
      : display(SCREEN_WIDTH, SCREEN_HEIGHT, &SPI, OLED_DC, OLED_RESET, OLED_CS), line(0) {}

  void begin() {
    delay(250);                 // Wait for the OLED to power up
    display.begin(0x3D, true);  // Address 0x3D default
    display.display();
    delay(1000);

    // Set display configurations
    display.setRotation(0);
    display.setTextColor(SH110X_WHITE);
    display.setTextSize(1);
    display.clearDisplay();
  }

  void showStatus(bool isAlice, SecurityLevel currentLevel) {
    // Display large text for the current security level
    display.clearDisplay();
    display.setTextSize(2);                         // Large text
    display.setCursor(10, SCREEN_HEIGHT / 2 - 10);  // Centered text
    if (currentLevel == LEVEL0) {
      display.println("LEVEL 0");
    } else if (currentLevel == LEVEL1) {
      display.println("LEVEL 1");
    } else {
      display.println("LEVEL 2");
    }
    display.print(isAlice ? "Alice" : "Bob");

    display.display();
    delay(1000);  // Flash the message for 1 second
    display.clearDisplay();
    display.setTextSize(1);  // Reset text size for normal use
  }

  void scrollDisplay() {
    display.clearDisplay();

    // Shift all lines up by one in the buffer
    for (int i = 1; i < maxLines; i++) {
      messageBuffer[i - 1] = messageBuffer[i];
    }
    messageBuffer[maxLines - 1] = "";  // Clear the last line
    line--;                            // Adjust line counter

    // Redraw all lines from the buffer
    for (int i = 0; i < line; i++) {
      display.setCursor(0, i * lineHeight);
      display.print(messageBuffer[i]);
    }
    display.display();
  }

  void displayMessage(const char *formattedMessage) {
    // Check if we've reached the maximum lines, scroll if needed
    if (line >= maxLines) {
      scrollDisplay();
    }

    // Add the formatted message to the buffer and display it
    messageBuffer[line] = formattedMessage;
    display.setCursor(0, line * lineHeight);
    display.print(formattedMessage);
    display.display();

    line++;  // Move to the next line
  }

  void setTextSize(uint8_t size) {
    display.setTextSize(size);
  }

private:
  Adafruit_SH1107 display;
  String messageBuffer[maxLines];
  int line;
};

// DiffieHellmanManager handles the DH key exchange process
class DiffieHellmanManager {
public:
  DiffieHellmanManager(DisplayManager &displayManager)
      : displayManager(displayManager), state(IDLE), sharedKeyAvailable(false) {}

  void initiate(bool isAlice);
  void processMessage(const char *message, bool isAlice);
  bool isSharedKeyAvailable() { return sharedKeyAvailable; }
  int getSharedKey() { return sharedKey; }
  void reset() {
    state = IDLE;
    sharedKeyAvailable = false;
  }

private:
  DisplayManager &displayManager;
  enum State {
    IDLE,
    SENT_PG,
    RECEIVED_ACK,
    SENT_A_PREKEY,
    RECEIVED_B_PREKEY
  };
  State state;
  bool sharedKeyAvailable;
  int sharedKey;

  // DH parameters
  long p;
  long g;
  int privateKey;
  long publicKey;
  long remotePublicKey;
};

void DiffieHellmanManager::initiate(bool isAlice) {
  if (isAlice && state == IDLE) {
    // Alice sends p and g
    p = 2089;  // Large prime number
    g = 2;     // Primitive root modulo p
    String message = "PG:" + String(p) + "," + String(g);
    // Do not display p and g on the screen
    Serial1.println(message);
    state = SENT_PG;
  }
}

void DiffieHellmanManager::processMessage(const char *message, bool isAlice) {
  String msgStr = String(message);

  if (msgStr.startsWith("PG:")) {
    // Bob receives p and g, replies with ACK
    if (!isAlice && state == IDLE) {
      String params = msgStr.substring(3);
      int commaIndex = params.indexOf(',');
      p = params.substring(0, commaIndex).toInt();
      g = params.substring(commaIndex + 1).toInt();

      // Send ACK
      String ackMessage = "ACK";
      Serial1.println(ackMessage);
      state = RECEIVED_ACK;
    }
  } else if (msgStr.startsWith("ACK")) {
    // Alice receives ACK, sends Alice-Pre-Key
    if (isAlice && state == SENT_PG) {
      // Generate private and public keys
      privateKey = random(2, p - 2);
      publicKey = modExp(g, privateKey, p);
      String preKeyMessage = "AKEY:" + String(publicKey);
      Serial1.println(preKeyMessage);
      state = RECEIVED_ACK;
    }
  } else if (msgStr.startsWith("AKEY:")) {
    // Bob receives Alice-Pre-Key, sends Bob-Pre-Key
    if (!isAlice && state == RECEIVED_ACK) {
      String keyStr = msgStr.substring(5);
      remotePublicKey = keyStr.toInt();

      // Generate private and public keys
      privateKey = random(2, p - 2);
      publicKey = modExp(g, privateKey, p);

      // Compute shared key
      sharedKey = modExp(remotePublicKey, privateKey, p);
      sharedKeyAvailable = true;

      String preKeyMessage = "BKEY:" + String(publicKey);
      Serial1.println(preKeyMessage);
      state = RECEIVED_B_PREKEY;
    }
  } else if (msgStr.startsWith("BKEY:")) {
    // Alice receives Bob-Pre-Key, computes shared key
    if (isAlice && state == RECEIVED_ACK) {
      String keyStr = msgStr.substring(5);
      remotePublicKey = keyStr.toInt();

      // Compute shared key
      sharedKey = modExp(remotePublicKey, privateKey, p);
      sharedKeyAvailable = true;
      state = RECEIVED_B_PREKEY;
    }
  }
}

// CommunicationManager class handles sending and receiving messages
class CommunicationManager {
public:
  CommunicationManager(DisplayManager &displayManager, DiffieHellmanManager &dhManager)
      : displayManager(displayManager), dhManager(dhManager) {}

  void begin() {
    Serial1.begin(9600);
  }

  void sendPlainText(const char *message) {
    // Display only the plain text message
    displayManager.displayMessage(("Sent: " + String(message)).c_str());
    Serial1.println(message);
  }

  void sendEncrypted(const char *message) {
    // Encrypt the message using the shared key (simple XOR encryption)
    String encryptedMessage = encryptMessage(message);
    // Do not display the encrypted message
    Serial1.println(encryptedMessage);
  }

  void onReceive(bool isAlice, SecurityLevel currentLevel);

  // Simple encryption/decryption
  String encryptMessage(const char *plainText);
  String decryptMessage(const char *cipherText);

private:
  DisplayManager &displayManager;
  DiffieHellmanManager &dhManager;
};

void CommunicationManager::onReceive(bool isAlice, SecurityLevel currentLevel) {
  if (Serial1.available() > 0) {
    String receivedMessage = Serial1.readStringUntil('\n');

    if (currentLevel == LEVEL0) {
      // Level 0: Plain-text communication
      displayManager.displayMessage(("Recv: " + receivedMessage).c_str());
    } else if (currentLevel == LEVEL1) {
      // Level 1: Encrypted communication
      if (receivedMessage.startsWith("PG:") || receivedMessage.startsWith("ACK") ||
          receivedMessage.startsWith("AKEY:") || receivedMessage.startsWith("BKEY:")) {
        // Process Diffie-Hellman key exchange messages
        dhManager.processMessage(receivedMessage.c_str(), isAlice);
      } else {
        if (dhManager.isSharedKeyAvailable()) {
          String decryptedMessage = decryptMessage(receivedMessage.c_str());
          // Display only the decrypted plain text message
          displayManager.displayMessage(("Recv: " + decryptedMessage).c_str());
        } else {
          // Display a message indicating the shared key is not available
          displayManager.displayMessage("Shared key not available");
        }
      }
    }
  }
}

String CommunicationManager::encryptMessage(const char *plainText) {
  // Simple XOR encryption with sharedKey
  int key = dhManager.getSharedKey() % 256;
  String encryptedText = "";
  for (size_t i = 0; i < strlen(plainText); i++) {
    char encryptedChar = plainText[i] ^ key;
    encryptedText += String((int)encryptedChar) + " ";  // Store ASCII values
  }
  return encryptedText;
}

String CommunicationManager::decryptMessage(const char *cipherText) {
  // Simple XOR decryption with sharedKey
  int key = dhManager.getSharedKey() % 256;
  String decryptedText = "";
  String cipherStr = String(cipherText);
  int start = 0;
  int end = cipherStr.indexOf(' ');
  while (end != -1) {
    String charCodeStr = cipherStr.substring(start, end);
    char encryptedChar = (char)charCodeStr.toInt();
    char decryptedChar = encryptedChar ^ key;
    decryptedText += decryptedChar;
    start = end + 1;
    end = cipherStr.indexOf(' ', start);
  }
  return decryptedText;
}

// LevelManager handles the different security levels
class LevelManager {
public:
  LevelManager()
      : currentLevel(LEVEL0) {}

  void nextLevel() {
    currentLevel = static_cast<SecurityLevel>((currentLevel + 1) % 2);  // LEVEL0 and LEVEL1
  }

  SecurityLevel getCurrentLevel() {
    return currentLevel;
  }

private:
  SecurityLevel currentLevel;
};

// Alice class contains the logic specific to Alice
class Alice {
public:
  Alice(CommunicationManager &commManager, DiffieHellmanManager &dhManager)
      : commManager(commManager), dhManager(dhManager), sequenceNumber(1), lastSendTime(0), dhInitiated(false) {}

  void run(SecurityLevel currentLevel) {
    if (currentLevel == LEVEL0) {
      // Level 0: Plain-text communication
      level0();
    } else if (currentLevel == LEVEL1) {
      // Level 1: Encrypted communication with DH key exchange
      level1();
    }
  }

private:
  void level0() {
    // Check if it's time to send a new message
    unsigned long currentMillis = millis();
    if (currentMillis - lastSendTime >= sendInterval) {
      // Alice sends a plain-text message
      String message = "Message " + String(sequenceNumber);
      commManager.sendPlainText(message.c_str());
      sequenceNumber++;

      lastSendTime = currentMillis;
    }
  }

  void level1() {
    if (!dhInitiated) {
      // Initiate Diffie-Hellman key exchange
      dhManager.reset();  // Reset DH manager state
      dhManager.initiate(true);
      dhInitiated = true;
    }

    if (dhManager.isSharedKeyAvailable()) {
      // Send test messages if not already sent
      if (!testMessagesSent) {
        // Send Plain_Message_1 and Enc_Message_2
        String plainMessage = "Plain_Message_1";
        commManager.sendPlainText(plainMessage.c_str());

        String encryptedMessage = "Enc_Message_2";
        commManager.sendEncrypted(encryptedMessage.c_str());

        testMessagesSent = true;
        lastSendTime = millis();  // Reset the send timer
      } else {
        // Continue sending encrypted messages periodically
        unsigned long currentMillis = millis();
        if (currentMillis - lastSendTime >= sendInterval) {
          String message = "New " + String(sequenceNumber);
          commManager.sendEncrypted(message.c_str());
          sequenceNumber++;

          lastSendTime = currentMillis;
        }
      }
    }
  }

  CommunicationManager &commManager;
  DiffieHellmanManager &dhManager;
  int sequenceNumber;
  unsigned long lastSendTime;
  bool dhInitiated;
  bool testMessagesSent = false;
};

// Bob class contains the logic specific to Bob
class Bob {
public:
  Bob(CommunicationManager &commManager, DiffieHellmanManager &dhManager)
      : commManager(commManager), dhManager(dhManager), sequenceNumber(1), dhInitiated(false) {}

  void run(SecurityLevel currentLevel) {
    if (currentLevel == LEVEL0) {
      // Level 0: Plain-text communication
      // Bob's logic for Level 0 can be added here if needed
    } else if (currentLevel == LEVEL1) {
      // Level 1: Encrypted communication with DH key exchange
      level1();
    }
  }

private:
  void level1() {
    if (!dhInitiated) {
      // Wait for Alice to initiate DH key exchange
      dhManager.reset();  // Reset DH manager state
      dhInitiated = true;
    }

    if (dhManager.isSharedKeyAvailable()) {
      if (!testMessagesSent) {
        // Send Enc_Message_1 and Plain_Message_2
        String encryptedMessage = "Enc_Message_1";
        commManager.sendEncrypted(encryptedMessage.c_str());

        String plainMessage = "Plain_Message_2";
        commManager.sendPlainText(plainMessage.c_str());

        testMessagesSent = true;
        lastSendTime = millis();  // Reset the send timer
      } else {
        // Continue sending encrypted messages periodically
        unsigned long currentMillis = millis();
        if (currentMillis - lastSendTime >= sendInterval) {
          String message = "Rep " + String(sequenceNumber);
          commManager.sendEncrypted(message.c_str());
          sequenceNumber++;

          lastSendTime = currentMillis;
        }
      }
    }
  }

  CommunicationManager &commManager;
  DiffieHellmanManager &dhManager;
  int sequenceNumber;
  bool dhInitiated;
  bool testMessagesSent = false;
  unsigned long lastSendTime = 0;
};

// Global variables
bool isAlice = true;

// Instances
DisplayManager displayManager;
LevelManager levelManager;
DiffieHellmanManager dhManager(displayManager);
CommunicationManager commManager(displayManager, dhManager);
Alice *alice = nullptr;
Bob *bob = nullptr;

void setup() {
  // Initialize pins
  pinMode(MODE_SELECT, INPUT_PULLUP);  // Set mode select pin as input with pull-up resistor
  pinMode(IS_ALICE, INPUT_PULLUP);     // Set Alice/Bob mode select pin as input with pull-up resistor

  // Determine if the device is Alice or Bob
  isAlice = digitalRead(IS_ALICE) == LOW;

  // Initialize display
  displayManager.begin();

  randomSeed(analogRead(0));  // Seed for random number generation

  // Initialize communication
  commManager.begin();

  // Show status
  displayManager.showStatus(isAlice, levelManager.getCurrentLevel());

  // Initialize Alice or Bob
  if (isAlice) {
    alice = new Alice(commManager, dhManager);
  } else {
    bob = new Bob(commManager, dhManager);
  }
}

void loop() {
  if (digitalRead(MODE_SELECT) == LOW) {
    delay(50);  // Initial debounce delay
    if (digitalRead(MODE_SELECT) == LOW) {
      levelManager.nextLevel();
      displayManager.showStatus(isAlice, levelManager.getCurrentLevel());

      // Reset DH state when changing levels
      dhManager.reset();
      if (alice != nullptr) {
        delete alice;
        alice = new Alice(commManager, dhManager);
      }
      if (bob != nullptr) {
        delete bob;
        bob = new Bob(commManager, dhManager);
      }

      while (digitalRead(MODE_SELECT) == LOW) {
        delay(50);  // Wait until the button is released
      }
    }
  }

  // Both Alice and Bob check for incoming messages
  commManager.onRecei`ve(isAlice, levelManager.getCurrentLevel());

  if (isAlice && alice != nullptr) {
    alice->run(levelManager.getCurrentLevel());  // Alice runs her logic based on the security level
  } else if (bob != nullptr) {
    bob->run(levelManager.getCurrentLevel());    // Bob runs his logic based on the security level
  }
}
