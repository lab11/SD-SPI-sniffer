git # SDSPI from SPI

This is a high-level analyzer (HLA) for decoding SD SPI comminication with a Saleae logic analyzer.

## Setup

To use this extension, do the following:

### Install Saleae Logic 2

As of the time of writing, the latest version was v2.3.2.

### Install this extension

1. Download all files to a directory on your computer

2. In the "Extensions" tab, select "Create Extension" and select "Load existing extension."

3. Select the "extension.json" file on your computer.

### Create an SPI analyzer

1. MOSI mapped to SDIO_CMD
  
2. MISO mapped to DATA 0
  
3. Clock mapped to SDIO/CK

4. Enable mapped to CD
  
5. MSB first
  
6. 8 bits per transfer
  
7. CPOL = 0
  
8. CPHA = 0

### Create an "SDSPI from SPI" analyzer

Use the SPI analyzer above as the input.


## Notes

This extension is not compatible with Saleae Logic 1.x.

# To do 
- Remove errors for multiple reads and writes
- Check CRC
- Better detection of data  block
- Improve readability
- resolve application specific command
- verify comand list
- better code readability fo response types
- better error message for error at line 499
- error on CMD 9


# Acknolegements
this project is based on the SDMMC from SPI analyser by Tim Kostka
orignal repo : https://github.com/timkostka/saleae_sdmmc_from_spi
