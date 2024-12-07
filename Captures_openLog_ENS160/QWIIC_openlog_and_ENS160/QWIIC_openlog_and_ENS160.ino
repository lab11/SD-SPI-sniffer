/*
  An I2C based datalogger - Like the OpenLog but for I2C
  By: Nathan Seidle
  SparkFun Electronics
  Date: February 2nd, 2018
  License: This code is public domain but you buy me a beer if you use this and we meet someday (Beerware license).

  This example shows how to record various text and variables to Qwiic OpenLog

  To Use:
    Insert a formatted SD card into Qwiic OpenLog
    Attach Qwiic OpenLog to a RedBoard or Uno with a Qwiic cable
    Load this sketch onto the RedBoard
    Open a terminal window to see the Serial.print statements
    Then insert the SD card into a computer view the log file contents
*/

#include <Wire.h>
#include "SparkFun_Qwiic_OpenLog_Arduino_Library.h"
#include "SparkFun_ENS160.h"
OpenLog myLog; //Create instance

int ledPin = LED_BUILTIN; //Status LED connected to digital pin 13
SparkFun_ENS160 myENS; 
int ensStatus; 


void setup()
{
  pinMode(ledPin, OUTPUT);

  Wire.begin(); //Initialize I2C
  myLog.begin(); //Open connection to OpenLog (no pun intended)

  if( !myENS.begin() )
	{
		Serial.println("Could not communicate with the ENS160, check wiring.");
		while(1);
	}

  Serial.begin(9600); //9600bps is used for debug statements
  Serial.println("OpenLog Write File Test");
  
  //Record something to the default log
  myLog.println("This goes to the log file");
  Serial.println("This goes to the terminal");

  
	// Reset the indoor air quality sensor's settings.
	if( myENS.setOperatingMode(SFE_ENS160_RESET) )
		Serial.println("Ready.");

	delay(100);

	// Device needs to be set to idle to apply any settings.
	// myENS.setOperatingMode(SFE_ENS160_IDLE);

	// Set to standard operation
	// Others include SFE_ENS160_DEEP_SLEEP and SFE_ENS160_IDLE
	myENS.setOperatingMode(SFE_ENS160_STANDARD);

	// There are four values here: 
	// 0 - Operating ok: Standard Operation
	// 1 - Warm-up: occurs for 3 minutes after power-on.
	// 2 - Initial Start-up: Occurs for the first hour of operation.
  //												and only once in sensor's lifetime.
	// 3 - No Valid Output
	ensStatus = myENS.getFlags();
	Serial.print("Gas Sensor Status Flag (0 - Standard, 1 - Warm up, 2 - Initial Start Up): ");
	Serial.println(ensStatus);
  

}
void loop()
{

  if( myENS.checkDataStatus() )
	{
		myLog.print("Air Quality Index (1-5) : ");
		myLog.println(myENS.getAQI());

		myLog.print("Total Volatile Organic Compounds: ");
		myLog.print(myENS.getTVOC());
		myLog.println("ppb");

		myLog.print("CO2 concentration: ");
		myLog.print(myENS.getECO2());
		myLog.println("ppm");
	

    myLog.print("Gas Sensor Status Flag (0 - Standard, 1 - Warm up, 2 - Initial Start Up): ");
    myLog.println(myENS.getFlags());

	  myLog.println();

    //myLog.read(uint8_t *userBuffer, uint16_t bufferSize, String fileName)

  }else{
    myLog.println("no data");
  }
	
  
  myLog.syncFile();

  Serial.println(F("Done!"));

  delay(100);

}
