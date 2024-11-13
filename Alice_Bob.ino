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

// CommunicationManager class handles sending and receiving messages
class CommunicationManager {
public:
  CommunicationManager(DisplayManager &displayManager)
      : displayManager(displayManager), sharedKeyAvailable(false) {}

  void begin() {
    Serial1.begin(9600);
  }

  void sendPlainText(const char *message) {
    displayManager.displayMessage(("-> " + String(message)).c_str());
    Serial1.println(message);
  }

  void sendEncrypted(const char *message) {
    // Encrypt the message using the shared key (simple XOR encryption)
    String encryptedMessage = encryptMessage(message);
    displayManager.displayMessage(("-> " + encryptedMessage).c_str());
    Serial1.println(encryptedMessage);
  }

  void onReceive(bool isAlice, SecurityLevel currentLevel);

  // Diffie-Hellman key exchange functions
  void initiateDH(bool isAlice);
  void processDHMessage(const char *message);

  // Simple encryption/decryption
  String encryptMessage(const char *plainText);
  String decryptMessage(const char *cipherText);

  bool sharedKeyAvailable;
  int sharedKey;

private:
  DisplayManager &displayManager;
  // Diffie-Hellman variables
  int p;        // Prime modulus
  int g;        // Primitive root modulo p
  int privateKey;
  int publicKey;
  int remotePublicKey;
};

void CommunicationManager::onReceive(bool isAlice, SecurityLevel currentLevel) {
  if (Serial1.available() > 0) {
    String receivedMessage = Serial1.readStringUntil('\n');

    if (currentLevel == LEVEL0) {
      // Level 0: Plain-text communication
      displayManager.displayMessage(("<- " + receivedMessage).c_str());
    } else if (currentLevel == LEVEL1) {
      // Level 1: Encrypted communication
      if (receivedMessage.startsWith("DH:")) {
        // Process Diffie-Hellman key exchange message
        processDHMessage(receivedMessage.c_str());
      } else {
        // Encrypted message
        displayManager.displayMessage(("<- " + receivedMessage).c_str());

        if (sharedKeyAvailable) {
          String decryptedMessage = decryptMessage(receivedMessage.c_str());
          displayManager.displayMessage(("Decrypted: " + decryptedMessage).c_str());
        } else {
          displayManager.displayMessage("Shared key not available");
        }
      }
    }
  }
}

void CommunicationManager::initiateDH(bool isAlice) {
  // Use small prime numbers for p and g
  p = 23;  // Prime modulus
  g = 5;   // Primitive root modulo p

  // Generate private key (random number less than p)
  privateKey = random(1, p);
  // Compute public key
  publicKey = (int)pow(g, privateKey) % p;

  // Send public key
  String message = "DH:" + String(publicKey);
  displayManager.displayMessage(("-> " + message).c_str());
  Serial1.println(message);
}

void CommunicationManager::processDHMessage(const char *message) {
  // Extract public key from message
  String msgStr = String(message);
  remotePublicKey = msgStr.substring(3).toInt();

  // Compute shared secret
  int sharedSecret = (int)pow(remotePublicKey, privateKey) % p;
  sharedKey = sharedSecret;
  sharedKeyAvailable = true;

  displayManager.displayMessage(("Shared key: " + String(sharedKey)).c_str());
}

String CommunicationManager::encryptMessage(const char *plainText) {
  // Simple XOR encryption with sharedKey
  String encryptedText = "";
  for (size_t i = 0; i < strlen(plainText); i++) {
    char encryptedChar = plainText[i] ^ sharedKey;
    encryptedText += String((int)encryptedChar) + " ";  // Store ASCII values
  }
  return encryptedText;
}

String CommunicationManager::decryptMessage(const char *cipherText) {
  // Simple XOR decryption with sharedKey
  String decryptedText = "";
  String cipherStr = String(cipherText);
  int start = 0;
  int end = cipherStr.indexOf(' ');
  while (end != -1) {
    String charCodeStr = cipherStr.substring(start, end);
    char encryptedChar = (char)charCodeStr.toInt();
    char decryptedChar = encryptedChar ^ sharedKey;
    decryptedText += decryptedChar;
    start = end + 1;
    end = cipherStr.indexOf(' ', start);
  }
  return decryptedText;
}

// Alice class contains the logic specific to Alice
class Alice {
public:
  Alice(CommunicationManager &commManager)
      : commManager(commManager), sequenceNumber(1), lastSendTime(0), dhInitiated(false) {}

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
      commManager.initiateDH(true);
      dhInitiated = true;
    }

    if (commManager.sharedKeyAvailable) {
      // Check if it's time to send a new message
      unsigned long currentMillis = millis();
      if (currentMillis - lastSendTime >= sendInterval) {
        // Alice sends an encrypted message
        String message = "Secret " + String(sequenceNumber);
        commManager.sendEncrypted(message.c_str());

        sequenceNumber++;
        lastSendTime = currentMillis;
      }
    }
  }

  CommunicationManager &commManager;
  int sequenceNumber;
  unsigned long lastSendTime;
  bool dhInitiated;
};

// Bob class contains the logic specific to Bob
class Bob {
public:
  Bob(CommunicationManager &commManager)
      : commManager(commManager), sequenceNumber(1), dhInitiated(false) {}

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
      // Initiate Diffie-Hellman key exchange
      commManager.initiateDH(false);
      dhInitiated = true;
    }

    if (commManager.sharedKeyAvailable) {
      // Bob can send encrypted messages back to Alice
      // For demonstration, Bob replies when he receives a message
      unsigned long currentMillis = millis();
      if (currentMillis - lastReplyTime >= sendInterval) {
        String message = "Reply " + String(sequenceNumber);
        commManager.sendEncrypted(message.c_str());
        sequenceNumber++;
        lastReplyTime = currentMillis;
      }
    }
  }

  CommunicationManager &commManager;
  int sequenceNumber;
  bool dhInitiated;
  unsigned long lastReplyTime = 0;
};

// Global variables
bool isAlice = true;
SecurityLevel currentLevel = LEVEL0;

// Instances
DisplayManager displayManager;
CommunicationManager commManager(displayManager);
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
  displayManager.showStatus(isAlice, currentLevel);

  // Initialize Alice or Bob
  if (isAlice) {
    alice = new Alice(commManager);
  } else {
    bob = new Bob(commManager);
  }
}

void nextSecurityLevel() {
  // Increment the security level
  currentLevel = static_cast<SecurityLevel>((currentLevel + 1) % 2);  // Only LEVEL0 and LEVEL1
  displayManager.showStatus(isAlice, currentLevel);
}

void loop() {
  if (digitalRead(MODE_SELECT) == LOW) {
    delay(50);  // Initial debounce delay
    if (digitalRead(MODE_SELECT) == LOW) {
      nextSecurityLevel();
      while (digitalRead(MODE_SELECT) == LOW) {
        delay(50);  // Wait until the button is released
      }
    }
  }

  // Both Alice and Bob check for incoming messages
  commManager.onReceive(isAlice, currentLevel);

  if (isAlice && alice != nullptr) {
    alice->run(currentLevel);  // Alice runs her logic based on the security level
  } else if (bob != nullptr) {
    bob->run(currentLevel);    // Bob runs his logic based on the security level
  }
}
