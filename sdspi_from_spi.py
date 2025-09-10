"""
High Level Analyzer script for interpreting SDSPI communication.

This is supported by Saleae Logic v2.3.1 or later.

For more information, see https://github.com/saleae/logic2-examples

Authors: Paul de La Sayette, Jash Gujarathi

Forked from the original script by Tim Kostka :
https://github.com/timkostka/saleae_sdmmc_from_spi

"""

"""
TO DO :
- Add R4
- better message type readability
- check command and response
- better timimg visualization

"""




## imports 
from saleae.data.timing import GraphTimeDelta
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting
import importlib.util
import traceback
import platform
from enum import IntEnum, Enum
from typing import Optional
import argparse
import csv
import re
from collections import deque


# states (CURRENT_STATE)
# to do : use them to be easier to read
MESSAGE_TYPE = {
    0: "COMMAND",
    1: "RESPONSE1",
    2: "RESPONSE2",
    3: "RESPONSE3",
    5: "RESPONSE5",
    7: "RESPONSE7",
    10: "ACK_DATA_BLOCK_MOSI",
    11: "ACK_DATA_BLOCK_MISO",
    12: "DATA_BLOCK_MOSI",
    13: "DATA_BLOCK_MISO",
}


# states (CURRENT_STATE)
CURRENT_STATE = {
    0: "IDLE",
    1: "READY",
    2: "IDENTIFICATION",
    3: "STANDBY",
    4: "TRANSFER",
    5: "DATA",
    6: "RECEIVE",
    7: "PROGRAMMING",
    8: "DISCONNECT",
    9: "BUS TEST",
    10: "SLEEP",
}

# command value info
# tuple is (name, response)
# response of 0 means no response
COMMAND_INFO = {
    # Basic commands (class 0 and class 1)
    0: ("GO_IDLE_STATE", 1),
    1: ("SEND_OP_COND", 1),
    2: ("NOT IMPLEMENTED IN SPI: ALL_SEND_CID", 2),
    3: ("NOT IMPLEMENTED IN SPI: SET_RELATIVE_ADDR", 1),
    4: ("NOT IMPLEMENTED IN SPI: SET_DSR", None),
    5: ("SLEEP_AWAKE", 1),
    6: ("SWITCH", 1),
    7: ("NOT IMPLEMENTED IN SPI: SELECT_CARD", 1),
    8: ("SEND_IF_COND", 7),
    9: ("SEND_CSD", 1),
    10: ("SEND_CID", 1),
    11: ("obsolete", None),
    12: ("STOP_TRANSMISSION", 1),
    13: ("SEND_STATUS", 2),
    14: ("BUSTEST_R", 1),
    15: ("NOT IMPLEMENTED IN SPI: GO_INACTIVE_STATE", None),
    19: ("BUSTEST_W", 1),
    # Block-oriented read commands (class 2)
    16: ("SET_BLOCKLEN", 1),
    17: ("READ_SINGLE_BLOCK", 11),
    18: ("READ_MULTIPLE_BLOCK", 11),
    21: ("SEND_TUNING_BLOCK", 11 ),
    # Class 3 commands
    20: ("obsolete", None),
    22: ("reserved", None),
    # Block-oriented write commands (class 4)
    23: ("SET_BLOCK_COUNT", 1),
    24: ("WRITE_BLOCK", 10),
    25: ("WRITE_MULTIPLE_BLOCK", 10),
    26: ("PROGRAM_CID", 1),
    27: ("PROGRAM_CSD", 1),
    49: ("SET_TIME", 1),
    # Block-oriented write protection commands (class 6)
    28: ("SET_WRITE_PROT", 1),
    29: ("CLR_WRITE_PROT", 1),
    30: ("SEND_WRITE_PROT", 1),
    31: ("SEND_WRITE_PROT_TYPE", 1),
    # Erase commands (class 5)
    35: ("ERASE_GROUP_START", 1),
    36: ("ERASE_GROUP_END", 1),
    38: ("ERASE", 1),
    # I/O mode commands (class 9)
    39: ("NOT IMPLEMENTED IN SPI: FAST_IO", 4),
    40: ("NOT IMPLEMENTED IN SPI: GO_IRQ_STATE", 5),
    41: ("Iniitialisation command",1),
    52: ("IO_RW_DIRECT", 5),
    # Lock Device commands (class 7)
    42: ("LOCK_UNLOCK", 1),
    # Command Queues (class 11)
    44: ("QUEUED_TASK_PARAMS", 1),
    45: ("QUEUED_TASK_ADDRESS", 1),
    46: ("EXECUTE_READ_TASK", 1),
    47: ("EXECUTE_WRITE_TASK", 1),
    48: ("CMDQ_TASK_MGMT", 1),
    # Application-specific commands (class 8)
    55: ("APP_CMD", 1),
    56: ("GEN_CMD", 1),
    # Security Protocols (class 1None)
    53: ("PROTOCOL_RD", 1),
    54: ("PROTOCOL_WR", 1),
    58 : ("READ OCR", 3)
}


def get_response_length(resp):
    """Return the length of the given response type."""
    if resp == 1:
        return 8
    if resp == 2:
        return 16
    elif resp == 5:
        return 16
    elif resp == 10 or resp == 11:
        return 8
    elif resp == 12 or resp == 13:
        return 515*8
    elif resp == 2:
        return 136
    elif resp == 7:
        return 40
    return 48


def get_command_name(cmd):
    """Return the command name from the command value."""
    if cmd in COMMAND_INFO:
        return COMMAND_INFO[cmd][0]
    return "unknown"


def get_command_response(cmd):
    """Return the response type from the given command value."""
    if cmd in COMMAND_INFO:
        return COMMAND_INFO[cmd][1]
    return None


def bits_from_byte(value):
    """"Return the bits from the byte."""
    return [bool(value & bit) for bit in [128, 64, 32, 16, 8, 4, 2, 1]]


def value_from_bits(bits):
    """Return an integer value given its bits."""
    value = 0
    for x in bits:
        value *= 2
        if x:
            value += 1
    return value


# to do : add theese in relevant classes

def interpret_command(bits):
    """Return a string description from the command bits."""
    assert len(bits) == 48, "bits length is %d, bits are %s, " %(len(bits),str(hex(value_from_bits(bits))))
    okay = True
    start_bit = bits[0]
    transmission_bit = bits[1]
    command_index = value_from_bits(bits[2:8])
    argument = value_from_bits(bits[8:40])
    crc7 = value_from_bits(bits[40:47])
    end_bit = value_from_bits(bits[47:48])
    if start_bit or not transmission_bit or not end_bit:
        okay = False
    if command_index in COMMAND_INFO:
        info = get_command_name(command_index) + " (CMD%d)" % command_index
        info += ", arg:%d" % argument
    else:
        info = "CMD%d" % command_index
        info += ", arg:%d" % argument
    if not okay:
        info += ", ERROR"
    return info


def interpret_data_block(bits):
    """Return a string description from the command bits."""
    #assert len(bits) == 48, "bits length is %d, bits are %s, " %(len(bits), hex(sum([(bits[i]==True)*2**(len(bits)-i) for i in range(len(bits))])))
    data_block_size = len(bits) - 8
    okay = True

    info = "DATA_BLOCK "
    # Convert the data block bits (excluding the first 8 bits) to an integer, then to hex
    data_bits = bits[8:]
    value = value_from_bits(data_bits)
    info += str(hex(value))

    if not okay:
        info += ", ERROR"
    return info


def interpret_response1(bits):
    """Return a string description from the response 1 bits."""
    #assert len(bits) == 8]
    okay = True
    start_bit = bits[0]
    command_index = value_from_bits(bits[2:8])
    in_busy_state = bits[7]
    info = "R1"
    #info += str(bits[0:11])
    if in_busy_state:
        info += ", BUSY"
    # add error flags
    if bits[1]:
        info += ", PARAM_ERROR"
    if bits[2]:
        info += ", ADDRESS_OUT_OF_RANGE"
    if bits[3]:
        info += ", ERASE_SEQUENCE_ERROR"
    if bits[4]:
        info += ", COM_CRC_ERROR"
    if bits[5]:
        info += ", ILLEGAL_COMMAND"
    if bits[6]:
        info += ", ERASE_RESET"
    
    if not okay:
        info += ", ERROR"

    return info


def interpret_response2(bits):
    """
    Physical Layer Specification 7.3.2.3
    in response to SEND_STAUS(CMD 13)
    Structure :
        Card is locked
        wp erase skip I lock/unl
        error
        CC error
        card ecc faileled
        wp violation
        erase param
        out of range / csd overwrite
        in idle state
        erase reset
        illegal command
        com crc error
        erase sequence error
        address error
        
    """

    assert len(bits) == 16

    info = "R2"
    if bits[1]:
        info += ", card is locked"
    if bits[2]:
        info += ", wp erase skip I lock/unl"
    if bits[3]:
        info += ", error"
    if bits[4]:
        info += ", CC error"
    if bits[5]:
        info += ", card ecc faileled"
    if bits[6]:
        info += ", wp violation"
    if bits[7]:
        info += ", erase param"
    if bits[8]:
        info += ", out of range / csd overwrite"
    if bits[9]:
        info += ", in idle state"
    if bits[10]:
        info += ", erase reset"
    if bits[11]:
        info += ", illegal command"
    if bits[12]:
        info += ", com crc error"
    if bits[13]:
        info += ", erase sequence error"
    if bits[14]:
        info += ", address error"
    if bits[15]:
        info += ", parameter error"

    return info


def interpret_response3(bits):
    """Return a string description from the response 3 bits."""
    assert len(bits) == 48
    okay = True
    start_bit = bits[0]
    transmission_bit = bits[1]
    index = bits[2:8]
    busy = bits[8]
    ccs = bits[9]
    uhs_ii_comaptible = bits[10]
    switching_accepted = bits[16]
    check_bits_1 = bits[2:8]
    ocr_register = bits[8:40]
    check_bits_2 = bits[40:47]
    end_bit = value_from_bits(bits[47:48])
    info = "R3, busy %s, ccs %s, uhs-ii-compatible %s, switching-accepted %s" % (busy, ccs, uhs_ii_comaptible, switching_accepted)
    return info


def interpret_response5(bits):
    """
    Return a string description from the response 5 bits.
    Defined in 5.2.2 SDIO simplified Spec Version 3
    Structure in order : Start Bit (1)
                         Parameter Error (1),
                         RFU (1) : Always 0
                         Function number error (1)
                         Com CRC Error (1)
                         Illegal Command (1)
                         RFU (1)
                         Busy State (1)
                         R/W Data (8 bits)
    """

    assert len(bits) == 16
    start_bit = bits[0]
    parameter_err = bits[1]
    function_err = bits[3]
    crc_err = bits[4]
    ill_command_err = bits[5]
    is_busy_state = bits[7]
    rw_data = bits[8:16]
    info = "R5 "
    if start_bit or parameter_err or function_err or crc_err or ill_command_err:
        info += ",ERROR "
        if start_bit:
            info += ",START_BIT_NOT_SET "
        if parameter_err:
            info += ",PARAM_ERR "
        if function_err:
            info += ",FUNC_ERR "
        if ill_command_err:
            info += ",ILLEGAL_CMD_ERR "
        if crc_err:
            info += ",CRC_ERR "
    if is_busy_state:
        info += ",BUSY_STATE "
    else:
        info += ",IDLE "
    info += ",{} ".format(rw_data)
    return info


def interpret_response7(bits):
    """
    Physical Layer Specification 7.3.2.6
    in response to SEND_IF_COND (CMD 8)
    Structure :
    [0 - 8] : R1
    [8 - 12] : Command Version
    [12 - 28] : Reserved bits
    [28 - 32] : Voltage Accepted
    [32 - 40 ] : Check Pattern
    """
    okay = True
    start_bit = bits[0]
    in_busy_state = bits[7]
    info = "R7"
    #info += str(bits[0:11])
    if in_busy_state:
        info += ", BUSY"
    # add error flags
    if bits[1]:
        info += ", PARAM_ERROR"
        okay = False
    if bits[2]:
        info += ", ADDRESS_OUT_OF_RANGE"
        okay = False
    if bits[3]:
        info += ", ERASE_SEQUENCE_ERROR"
        okay = False
    if bits[4]:
        info += ", COM_CRC_ERROR"
        okay = False
    if bits[5]:
        info += ", ILLEGAL_COMMAND"
        okay = False
    if bits[6]:
        info += ", ERASE_RESET"
        okay = False
    command_version = bits[8:12]
    voltage_accepted = bits[28:32]
    if voltage_accepted[3] != 1 :
        info += ", VOLTAGE_NOT_3.3 {}".format(voltage_accepted)
        okay = False
    else:
            info += ", VOLTAGE_3.3 {}".format(voltage_accepted)

    if not okay:
        info += ", ERROR"


    return info


class dataLineState:
        
    # class variables
    # response number expected, or None
    expected_message_type = None
    # this response number
    this_message_type = None
    # bits in the expected response
    expected_message_length = 48
    # value used during debugginng

    def __init__(self, debug_level):
        # bits leftover for the next command or response
        self.message_bits= None
        # start_time of the start of the command bits
        self.message_start = None
        # end time of the command bits
        self.message_end = None
        # time of first value
        self.first_time = None
        self.debug_level = debug_level
        self.log("\n\n\n")



    def debug(self, message):
        """Print debug message if debug level is set to verbose."""
        if self.debug_level == "Verbose":
            print(message)

    def log(self, message):
        """Log a message to the console."""
        if self.debug_level in ["Verbose", "Info", "Success"]:
            print(message)

    # to do : find a way to avoid duplicated code for MOSI and MISO
    # for example : create 2 different classes for mosi and miso communication

    def add_byte(self, value, start_time, end_time):
        """
        Add a byte of data and return a command, or None.

        start is the start time of the byte
        end is the end time of the byte

        """
        if isinstance(value, bytes):
            assert len(value) == 1
            value = value[0]
        assert isinstance(value, int)

        # if bus is idle, ignore value
        if (value == 255 ) and not self.message_bits:
            return None
        
        # if no message is expected, ignore value
        if (not self.is_message_expected(value)) and (self.message_bits is None):
            self.log("\033[33mWarning : byte received is %s but no message expected, byte is discarded\033[0m" % hex(value))
            return None

        #if there this is the first message, set the first time
        if not self.first_time:
            self.first_time = start_time
        new_bits = bits_from_byte(value)
        bit_length = GraphTimeDelta(float(end_time - start_time) / 7.5)

        # if this is the start of new message
        if not self.message_bits:
            count = 0
            # remove ones at the beginning if this is not a data block
            while new_bits[0] and dataLineState.expected_message_type < 10:
                count += 1
                del new_bits[0]
            self.message_start = start_time + GraphTimeDelta(count * float(bit_length))
            self.message_bits = new_bits
        else:
            # add bits to message
            self.message_bits += new_bits

        # if we don't have enough bits, return None
        if len(self.message_bits) < dataLineState.expected_message_length:
            return None
        
        # ! if we reached this point, we have a full response or a command

        this_message_length = dataLineState.expected_message_length
        dataLineState.this_message_type = dataLineState.expected_message_type

        # get end time of this message
        self.message_end = end_time - GraphTimeDelta(float(bit_length) * (
            len(self.message_bits) - this_message_length
        ))
        bits = self.message_bits[:this_message_length]
        self.log("\n")

        data = self.interpret_message(bits)

        #print the data in binary if small, in hex otherwise
        if len(bits)<= 136:
            self.log("bits (bin): "+ bin(value_from_bits(bits)))
            self.log("bits (hex): "+ hex(value_from_bits(bits)))
        else:
            self.log("bits (hex): "+ hex(value_from_bits(bits)))
            pass
        

        hex_data = hex(value_from_bits(bits))
        ascii_data = ""
        for i in range(2, len(hex_data), 2):
            #self.log("hex data: "+ hex_data[i:i+2])
            # print the data ascii character
            if len(hex_data[i:i+2]) == 2:
                #self.log("ascii data: "+ chr(int(hex_data[i:i+2], 16)))
                ascii_data += chr(int(hex_data[i:i+2], 16))

        #replace spaces with a dot
        ascii_data = ascii_data.replace(" ", ".")
        self.log("Ascii data: " + ascii_data)

        self.log(
            "start=%s, duration=%s"
            % (self.message_start, self.message_end - self.message_start)
        )
        return_data = {
            "message_start": self.message_start,
            "message_end": self.message_end,
            "data": data,
            "Ascii_data": ascii_data
        }
        self.message_bits = None
        self.debug("Expected next message type : %s" % dataLineState.expected_message_type)
        self.debug("Expected next message length : %s" % dataLineState.expected_message_length)
        return return_data

 

class mosiLineState (dataLineState):

    def interpret_message(self, bits):

        self.log("\033[1mMOSI message\033[0m")
        # determine if response or command
        transmission_bit = bits[1]
        first_byte = bits[0:8]
        if dataLineState.this_message_type == 12 and  first_byte == [1, 1, 1, 1, 1, 1, 0, 0]:
            data  = interpret_data_block(bits)
            dataLineState.expected_message_type = None
            dataLineState.expected_message_length = 48
            self.log("\031[1mERROR, This is a multiple block write which is not yet implemented in this software\033[0m")

        elif dataLineState.this_message_type == 12 and first_byte == [1, 1, 1, 1, 1, 1, 1 ,0]:
            data  = interpret_data_block(bits)
            dataLineState.expected_message_type = None
            dataLineState.expected_message_length = 48

        elif transmission_bit:
            data = interpret_command(bits)
            command_index = value_from_bits(bits[2:8])
            # if a command, set up the next expected response
            dataLineState.expected_message_type = get_command_response(command_index)
            dataLineState.expected_message_length = get_response_length(
                dataLineState.expected_message_type
            )
        elif dataLineState.this_message_type >= 12 :
            # if there is a data block on mosi line, we don't listen to the miso line
            bits = []
            data = ""
        else:
            dataLineState.expected_message_type = None
            dataLineState.expected_message_length = 48
            self.log("Unknown response type")
            data = "R%s" % dataLineState.this_message_type

        return data
           
    def is_message_expected(self, value):

        if dataLineState.expected_message_type == 12 and value in [252, 253, 254]:
            return True
        return dataLineState.expected_message_type is None

        
class misoLineState (dataLineState):
        
    def interpret_message(self, bits):
        """
        Add a byte of data and return a command, or None.

        start is the start time of the byte
        end is the end time of the byte

        """

        #if no expected response, ignore value
        

        self.log("\033[1mMISO message\033[0m")
        transmission_bit = bits[1]
        first_byte = bits[0:8]

        if dataLineState.this_message_type == 13 and first_byte == [1, 1, 1, 1, 1, 1, 1 ,0]:
            data  = interpret_data_block(bits)
            dataLineState.expected_message_type = None
            dataLineState.expected_message_length = 48
        else:
            dataLineState.expected_message_type = None
            dataLineState.expected_message_length = 48
            if dataLineState.this_message_type == 1 or dataLineState.this_message_type is None:
                data = interpret_response1(bits)
            elif dataLineState.this_message_type == 2:
                data = interpret_response2(bits)
            elif dataLineState.this_message_type == 3:
                data = interpret_response3(bits)
            elif dataLineState.this_message_type == 5:
                data = interpret_response5(bits)
            elif dataLineState.this_message_type == 7:
                data = interpret_response7(bits)
            elif dataLineState.this_message_type == 10:
                data = interpret_response1(bits)
                dataLineState.expected_message_type = 12
                dataLineState.expected_message_length = 515*8
            elif dataLineState.this_message_type == 11:
                data = interpret_response1(bits)
                dataLineState.expected_message_type = 13
                dataLineState.expected_message_length = 515*8
            elif dataLineState.this_message_type >= 12 :
                # if there is a data block on mosi line, we don't listen to the miso line
                bits = []
                data = ""
            else:
                self.log("Unknown response type")
                data = "R%s" % dataLineState.this_message_type

        return data
    
    def is_message_expected(self, value):
        if dataLineState.expected_message_type == 13 and value in [252, 253, 254]:
            return True
        return dataLineState.expected_message_type in [1,2,3,5,7,10,11]


class SdmmcFromSpiAnalyzer(HighLevelAnalyzer):
    # class to communicate with the analyzer using the API
    parse_FAT = ChoicesSetting(
        label='parse FAT32',
        choices = ['yes', 'no']
        )
    SDSPI_debug_level = ChoicesSetting(
        label='SDSPI debug level',
        choices=['Disabled', 'Error', 'Warning', 'Success', 'Info', 'Verbose']
    )
    FAT32_debug_level = ChoicesSetting(
        label='FAT32 debug level',
        choices=['Disabled', 'Error', 'Warning', 'Success', 'Info', 'Verbose']
    )

    last_end_time = None

    result_types = {
        "error": {"format": "ERROR"},
        "sdspi": {"format": "SDSPI: {{data.info}}"},
        "fat32" : {"format": "FAT: {{data.info}}"},
    }

    def __init__(self):
        self.mosi_state = mosiLineState(self.SDSPI_debug_level)
        self.miso_state = misoLineState(self.SDSPI_debug_level)

        print(f"Python version: {platform.python_version()}")

        if self.parse_FAT == "yes":
            # Try to load FAT32 parser from a known file path to avoid ambiguous module names
            self.sd_stream = SdStream() 
 
    def decode(self, data):

        mosi_data = None
        miso_data = None

        if "mosi" in data.data:
            value_mosi = data.data["mosi"]
            if isinstance(value_mosi, bytes):
                assert len(value_mosi) == 1
                value_mosi = value_mosi[0]
            assert isinstance(value_mosi, int)
            # if bus is idle, ignore value
            mosi_data = self.mosi_state.add_byte(value_mosi, data.start_time, data.end_time)
                

        if "miso" in data.data:
            value_miso = data.data["miso"]
            if isinstance(value_miso, bytes):
                assert len(value_miso) == 1
                value_miso = value_miso[0]
            assert isinstance(value_miso, int)

            #only work on the data if a message is expected
            if self.miso_state.expected_message_type :
                miso_data = self.miso_state.add_byte(value_miso, data.start_time, data.end_time)
                

        # To do : refactor this part
        
        if mosi_data:
            #mosi_data["message_start"] = mosi_data["message_end"]
            data = {
                "start_time": mosi_data["message_start"],
                "end_time": mosi_data["message_end"],
                "mosi_data": mosi_data["data"],
                "miso_data" : "",
                "Ascii_data": mosi_data["Ascii_data"]
            }
        elif miso_data: 
            #miso_data["message_start"] = miso_data["message_end"] 
            data = {
                "start_time": miso_data["message_start"],
                "end_time": miso_data["message_end"],
                "mosi_data": "",
                "miso_data" : miso_data["data"],
                "Ascii_data": miso_data["Ascii_data"]
            }
        elif mosi_data and miso_data:
            # not sure what to do here, but it shouldn't happen
            print("ERROR: both mosi and miso data")
            data = {
                "start_time": mosi_data["message_start"],
                "end_time": mosi_data["message_end"],
                "mosi_data": mosi_data["data"] + "error",
                "miso_data" : miso_data["data"] + "error",
                "Ascii_data": mosi_data["Ascii_data"]
            }
        else:
            return None
        
        # if times overlap, return an error
        if self.last_end_time is not None:
            assert data["start_time"] > self.last_end_time, "ERROR : time overlap : start time %s, last end time %s" % (data["start_time"], self.last_end_time)
        self.last_end_time = data["end_time"]


        if self.parse_FAT == "yes":

            fat_data = self.sd_stream.process_message(data["mosi_data"], data["miso_data"], current_log_level=self.FAT32_debug_level)
            if fat_data :
                if self.FAT32_debug_level == "Verbose" : print("FAT32 data: ", fat_data)
                return AnalyzerFrame(
                    'fat32',
                    data["start_time"],
                    data["end_time"],
                    {
                        "mosi_data": data["mosi_data"],
                        "miso_data": data["miso_data"],
                        "Ascii_data": data["Ascii_data"],
                        "type_of_block": fat_data.get("type_of_block"),
                        "address": fat_data.get("address"),
                        "changes": fat_data.get("changes"),
                        "info": fat_data.get("info"),
                    }
                )

        

        return AnalyzerFrame(
            'SD frame',
            data["start_time"],
            data["end_time"],
            {"mosi_data": data["mosi_data"],
            "miso_data": data["miso_data"], "Ascii_data": data["Ascii_data"]}
            #to do : have better visualtion of the data
        )


#=============================================== FAT32 parser integration ===============================================  

# ============================================= utils.py================================================================


# ANSI color codes dictionary for reuse
class Color(Enum):
    RESET = '\033[0m'
    BRIGHT = '\033[1m'
    WHITE = '\033[37m'
    GREEN = '\033[32m'
    RED = '\033[31m'
    MAGENTA = '\033[35m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    BLUE = '\033[34m'

class LogLevel(IntEnum):
    DISABLED = 0
    ERROR = 1
    ALERT = 2
    WARNING = 3
    SUCCESS = 4
    INFO = 5
    VERBOSE = 6

SECTOR_SIZE = 512
MASTER_BOOT_CODE_LENGTH = 446
PARTITION_TABLES_LENGTH = 16
BOOT_SIGNATURE_LENGTH = 2
BOOT_SECTOR_START = 0
FSINFO_SECTOR_START = 0
BOOT_SECTOR_SIZE = 512

PREDEFINED_VALUES = {
   "Boot_Flag": ["Bootable", "NOT Bootable"],
   "BytesPerSector": [0, 512, 1024, 2048, 4096],
   "SectorsPerCluster": [1, 2, 4, 8, 16, 32, 64, 128],
   "ClusterSize": 32768,                                    # Must be 32 KB or smaller
   "ReservedSectors": 32,                                   # FAT32 uses 32 (check if the number of reserved sectors is smaller greater than 32)
   "NrRootDirEntries": 0,                                   # Must be 0
   "SectorsPerFilesystem": 0,                               # Must be 0
   "MediaType": ['f8', 'f0'],
   "SectorsPerFat": 0,                                      # Must be 0
   "ExtendedBootSignature": "29",
   "FileSystemLabel": "FAT32   ",
   "BootSectorSignature": "aa55",
   "FSINFO_Signature1": "41615252",
   "FSINFO_Signature2": "61417272",
   "FSINFOSector_Signature": "aa550000",
}

def colorize(text, color):
    return color.value + text + Color.RESET.value


# --- Modified print_message using Color Enum for color names ---
def print_message(message, message_log_level=LogLevel.INFO, current_log_level=LogLevel.INFO):
    # Only print if the message's log_level is enabled by current_level
    if message_log_level <= current_log_level:
        # If the message is empty, print a blank line
        if message == "":
            print()
        # If the message is a string, add header based on the log level
        else:
            symbols = {
                LogLevel.VERBOSE: ('~', Color.CYAN),
                LogLevel.INFO: ('*', Color.BLUE),
                LogLevel.SUCCESS: ('+', Color.GREEN),
                LogLevel.WARNING: ('!', Color.YELLOW),
                LogLevel.ERROR: ('-', Color.RED),
                LogLevel.DISABLED: ('', Color.WHITE),
            }
            symbol, color_enum = symbols.get(message_log_level, ('?', Color.MAGENTA))
            print(colorize(f"[{colorize(symbol, color_enum)}] {message}", Color.RESET))

def print_docs(message, byte_range, size, essential=None, message_log_level=LogLevel.VERBOSE, current_log_level=LogLevel.VERBOSE):
    # Always call with message_log_level=LogLevel.VERBOSE
    if message_log_level <= current_log_level:
        if essential == "yes":
            label = f"[{colorize('ESSENTIAL', Color.GREEN)}] [{colorize(byte_range, Color.MAGENTA)}] {colorize(message, Color.YELLOW)} ({colorize(str(size) + ' byte' + ('s' if size != 1 else ''), Color.CYAN)})"
        elif essential == "no":
            label = f"[{colorize('NOT ESSENTIAL', Color.RED)}] [{colorize(byte_range, Color.MAGENTA)}] {colorize(message, Color.YELLOW)} ({colorize(str(size) + ' byte' + ('s' if size != 1 else ''), Color.CYAN)})"
        else:
            label = f"[{colorize(byte_range, Color.MAGENTA)}] {colorize(message, Color.YELLOW)} ({colorize(str(size) + ' byte' + ('s' if size != 1 else ''), Color.CYAN)})"
        print(colorize("\t" + label, Color.WHITE))


def display_message_info(address, message, info : dict, block_type, compare_to : Optional[dict] = None , message_log_level=LogLevel.VERBOSE, current_log_level=LogLevel.VERBOSE):

        changes : dict = {}
        if info is not None and not isinstance(info, dict):
            for key, value in info.items():
                if key in compare_to and compare_to[key] != value:
                    print_message(
                    f"Key {colorize(str(key), Color.YELLOW)} modified from {colorize(str(compare_to[key]), Color.RED)} to {colorize(str(value), Color.GREEN)}",
                    LogLevel.INFO, current_log_level
                    )
                    changes[key] = {"OLD": compare_to[key], "MODIFIED": value}
                elif key not in compare_to:
                    print_message(
                    f"Key {colorize(str(key), Color.YELLOW)} added with value {colorize(str(value), Color.GREEN)}",
                    LogLevel.INFO, current_log_level
                    )
                    changes[key] = {"ADDED": value}
            for key in compare_to:
                if key not in info:
                    print_message(
                    f"Key {colorize(str(key), Color.YELLOW)} deleted (was {colorize(str(compare_to[key]), Color.RED)})",
                    LogLevel.INFO, current_log_level
                    )
                    changes[key] = {"DELETED": compare_to[key]}
            

        return {
            "type_of_block": block_type,
            "address": address,
            "changes": dict_to_str(changes),
            "info": dict_to_str(info),
            "raw data": message,
        }

def dict_to_str(d, indent=1):
    if not isinstance(d, dict) or not d:
        return "{}"
    items = []
    ind = ' ' * indent
    for k, v in d.items():
        if isinstance(v, dict):
            v_str = dict_to_str(v, indent + 4)
            items.append(f"{ind}{repr(k)}: {v_str}")
        else:
            items.append(f"{ind}{repr(k)}: {repr(v)}")
    if indent == 0:
        return "{\n" + ",\n".join(items) + "\n}"
    else:
        return "{\n" + ",\n".join(items) + "\n" + ind + "}"

# Raw to Hex image converter:
def raw2hex(image_path, data=None, start=None):
    with open(image_path, 'rb') as f:
        if data is None and start is None:
            raw_data = f.read() 
        elif start is None:
            raw_data = f.read(data)
        elif data is not None and data is not None:
           f.seek(start)
           raw_data = f.read(data)

    return raw_data.hex()


# ============================================= main ====================================================================


class SdStream:
    def __init__(self):
        self.sd_card = Disk()  # Initialize the disk instance
        self.known_directories = []
        self.read_address = None
        self.write_address = None

    def process_sd_block(self, address, data, current_log_level=LogLevel.INFO):
        print_message(f"\nProcessing block at address {address}", LogLevel.INFO, current_log_level)
        print_message(f"self sd_card: {self.sd_card}, has the attribute partitions: {getattr(self.sd_card, 'partitions', [])}", LogLevel.VERBOSE, current_log_level)
        disk_instance = self.sd_card

        # Find the correct partition and FAT_file_system for the address
        partition = None
        FAT_file_system = None
        if hasattr(disk_instance, 'partitions'):
            for p in disk_instance.partitions:
                print(f"Checking partition with start sector LBA: {getattr(p, 'start_sector_lba', 'N/A')}")
                if hasattr(p, 'start_sector_lba') and address >= p.start_sector_lba:
                    partition = p
                    FAT_file_system = partition.FAT_file_system if hasattr(partition, 'FAT_file_system') else None
                    break

        if address == 0:
            old_info_mbr = disk_instance.info_mbr.copy()
            disk_instance.parse_MBR(data, current_log_level=current_log_level)
            return display_message_info(
                address, data, disk_instance.info_mbr, "MBR", current_log_level=current_log_level, compare_to=old_info_mbr
            )
        elif partition and address == partition.start_sector_lba:
            old_info_boot_sector = partition.info_boot_sector.copy()
            partition.parseBootSector(data, current_log_level=current_log_level)
            return display_message_info(
                address, data, partition.info_boot_sector, "Boot Sector", current_log_level=current_log_level, compare_to=old_info_boot_sector
            )

        elif FAT_file_system and hasattr(FAT_file_system, 'fsinfo_sector_number') and address == (partition.start_sector_lba + FAT_file_system.fsinfo_sector_number):
            message_to_display = display_message_info(
                address, data, None, "FSINFO Sector", current_log_level=current_log_level
            )
            # FAT_file_system.parse_FSINFO(data, current_log_level=current_log_level)
        elif FAT_file_system and hasattr(FAT_file_system, 'root_dir_cluster_number') and hasattr(FAT_file_system, 'sectors_per_cluster'):
            message_to_display = None
            # Compute first data sector according to FAT32 spec
            first_data_sector = partition.start_sector_lba + FAT_file_system.reserved_area + (FAT_file_system.num_of_fat * FAT_file_system.num_of_sectors_per_fat)
            root_dir_sector = first_data_sector + (FAT_file_system.root_dir_cluster_number - 2) * FAT_file_system.sectors_per_cluster

            if address == root_dir_sector:
                FAT_file_system.parse_root_directory(data, current_log_level=current_log_level)
                root_dir = FAT_file_system.root_dir
                if root_dir:
                    old_info_root = root_dir.info.copy()
                    # Traverse subdirectories and add their addresses
                    if hasattr(root_dir, 'children'):
                        for entry in root_dir.children:
                            if hasattr(entry, 'attr') and entry.attr and "D" in entry.attr and not "V" in entry.attr:
                                if hasattr(entry, 'first_cluster') and entry.first_cluster is not None:
                                    self.known_directories.append(entry)
                    message_to_display = display_message_info(
                        address, data, root_dir.info, "Root Directory", current_log_level=current_log_level, compare_to=old_info_root
                    )

            # Check if the address corresponds to any known directory and read it
            for entry in self.known_directories:
                if hasattr(entry, 'first_cluster') and entry.first_cluster is not None:
                    dir_sector = first_data_sector + (entry.first_cluster - 2) * FAT_file_system.sectors_per_cluster
                    if address == dir_sector:
                        old_info_entry = entry.info.copy() 
                        entry.parse_directory(data, current_log_level=LogLevel.VERBOSE)
                        message_to_display = display_message_info(
                            address, data, entry.info, entry.filename+ " Directory", current_log_level=current_log_level, compare_to=old_info_entry
                        )

                        if hasattr(entry, 'children'):
                            for subentry in entry.children:
                                if hasattr(subentry, 'attr') and subentry.attr and "D" in subentry.attr and not "V" in subentry.attr:
                                    if hasattr(subentry, 'first_cluster') and subentry.first_cluster is not None:
                                        # Check if already in known_directories by first_cluster
                                        if all(getattr(e, 'first_cluster', None) != subentry.first_cluster for e in self.known_directories):
                                            if hasattr(subentry, 'filename') and subentry.filename is not None:
                                                self.known_directories.append(subentry)
            if message_to_display:
                return message_to_display

        if partition and (address >= (partition.start_sector_lba + FAT_file_system.reserved_area) and address <= (partition.start_sector_lba + FAT_file_system.reserved_area + FAT_file_system.num_of_fat * FAT_file_system.num_of_sectors_per_fat)):
            print("\n")
            old_info_fat = FAT_file_system.info_fat.copy()
            FAT_file_system.parseFat(data, LogLevel.ERROR)
            return display_message_info(
                address, data, FAT_file_system.info_fat, "FAT table", compare_to = old_info_fat
            )



    def process_message(self, mosi_data, miso_data, current_log_level= LogLevel.INFO):

        if not isinstance(current_log_level, LogLevel):
            if isinstance(current_log_level, str) and current_log_level.upper() in LogLevel.__members__:
                current_log_level = LogLevel[current_log_level.upper()]
            else:
                raise ValueError("current_log_level must be an instance of LogLevel or a valid string.")

        # Check for CMD17 and extract address
        cmd17_match = re.match(r'READ_SINGLE_BLOCK \(CMD17\), arg:(\d+)', mosi_data)
        if cmd17_match:
            self.read_address = int(cmd17_match.group(1))
            print_message(f"Found CMD17 (read) with address: {self.read_address}", LogLevel.INFO, current_log_level)

        # Check for CMD24 (WRITE_SINGLE_BLOCK) and extract address
        cmd24_match = re.match(r'WRITE_BLOCK \(CMD24\), arg:(\d+)', mosi_data)
        if cmd24_match:
            self.write_address = int(cmd24_match.group(1))
            print_message(f"Found CMD24 (write) with address: {self.write_address}", LogLevel.INFO, current_log_level)

        # Check for DATA_BLOCK and use last_address
        if miso_data and miso_data.startswith('DATA_BLOCK') and self.read_address is not None:
            data_match = re.match(r'DATA_BLOCK 0x([0-9a-fA-F]+)', miso_data)
            if data_match:
                read_address = self.read_address  # Use the read address for processing
                self.read_address = None  # Reset after use
                data = data_match.group(1).strip()
                if len(data) < 1028:
                    data = data.zfill(1028)
                print_message("Found DATA_BLOCK: " + data[0:128], LogLevel.INFO, current_log_level)
                return self.process_sd_block(read_address, data, current_log_level=current_log_level)
            


        # Check for DATA_BLOCK and possible write (if you want to process writes)
        elif mosi_data and mosi_data.startswith('DATA_BLOCK') and self.write_address is not None:
            data_match = re.match(r'DATA_BLOCK 0x([0-9a-fA-F]+)', mosi_data)
            write_address = self.write_address  # Use the write address for processing
            self.write_address = None  # Reset after use
            if data_match:
                data = data_match.group(1).strip()
                if len(data) < 1028:
                    data = data.zfill(1028)
                print_message("Found WRITE DATA_BLOCK: " + data[0:128], LogLevel.INFO, current_log_level)
                return self.process_sd_block(write_address, data, current_log_level=current_log_level)


def process_csv_and_feed_blocks(args, current_log_level=LogLevel.INFO):
    """
    Reads the CSV file, finds each DATA_BLOCK row,
    gets the address from the previous CMD17 row,
    and calls process_sd_block(address, data).
    """

    sd_stream = SdStream()
    
    # Open the CSV file, replacing NUL characters with nothing to avoid errors
    with open(args.csv, newline='', encoding='utf-8', errors='replace') as csvfile:
        # Read and clean each line to remove NUL characters
        cleaned_lines = (line.replace('\x00', '') for line in csvfile)
        reader = csv.DictReader(cleaned_lines)
        for row in reader:
            #print("Processing row:", row)
            miso_data = row.get('miso_data', '')
            mosi_data = row.get('mosi_data', '')
            sd_stream.process_message(mosi_data, miso_data, current_log_level = current_log_level)


def process_image(args, current_log_level=LogLevel.INFO):
    # Parsing the Master Boot Record:
    image = raw2hex(args.image, SECTOR_SIZE)
    disk_instance = disk.Disk()
    disk_instance.parse_MBR(image, current_log_level=LogLevel.INFO)

    # Parsing Boot Sector of each FAT32 partition:
    for partition in disk_instance.partitions:
        if "FAT32" in partition.file_sys:
            image = raw2hex(args.image, 512, partition.start_sector_lba * SECTOR_SIZE)
            partition.parseBootSector(image, current_log_level=LogLevel.INFO)
            FAT_file_system = partition.FAT_file_system
            if FAT_file_system:
                # get the FAT entries
                image = raw2hex(args.image, 512, partition.start_sector_lba*SECTOR_SIZE + FAT_file_system.reserved_area*SECTOR_SIZE)
                FAT_file_system.parseFat(image, LogLevel.INFO)

                image = raw2hex(args.image, 512, partition.start_sector_lba*SECTOR_SIZE + FAT_file_system.fsinfo_sector_number*SECTOR_SIZE)
                FAT_file_system.parse_FSINFO(image, LogLevel.INFO)

                first_data_sector_number = partition.start_sector_lba + FAT_file_system.reserved_area + (FAT_file_system.num_of_fat * FAT_file_system.num_of_sectors_per_fat)
                root_dir_sector = first_data_sector_number + (FAT_file_system.root_dir_cluster_number - 2) * FAT_file_system.sectors_per_cluster
                image = raw2hex(args.image, 512, root_dir_sector * SECTOR_SIZE)
                FAT_file_system.parse_root_directory(image, LogLevel.INFO)


def bfs_subdirectories(disk, partition, FAT_file_system, root_dir, recursive_depth):
    queue = deque()
    queue.append((root_dir, 0))
    visited = set()

    while queue:
        current_dir, depth = queue.popleft()
        if depth > recursive_depth:
            continue
        for entry in current_dir.children:
            # Check if entry is a directory (by attribute string)
            if entry.attr and "D" in entry.attr and not "V" in entry.attr:
                dir_id = entry.first_cluster
                if dir_id is not None and dir_id not in visited:
                    visited.add(dir_id)
                    print_message(f"Directory: {entry.filename}, Depth: {depth}", LogLevel.INFO)
                    # If you want to parse the subdirectory's contents, you need to read its cluster and parse it
                    # This requires knowing how to get the cluster's data from the FAT_file_system
                    if hasattr(FAT_file_system, 'read_directory_cluster'):
                        subdir_image = FAT_file_system.read_directory_cluster(dir_id)
                        subdir = root_dir.DirectoryEntry()
                        subdir.filename = entry.filename
                        subdir.parse_directory(subdir_image, current_log_level=LogLevel.VERBOSE)
                        queue.append((subdir, depth + 1))
                else:
                    print_message(f"Skipping already visited or invalid directory: {entry.filename}", 'DEBUG')
            elif entry.attr and "A" in entry.attr:
                print_message(f"File: {entry.filename}, Depth: {depth}", LogLevel.INFO)




if __name__ == "__main__":
    
    try: 
        parser = argparse.ArgumentParser(description="Master Boot Record and FAT32 file system parser.")
        parser.add_argument("-i", "--image", help="Enter the path to the file system raw image", required=False)
        parser.add_argument("-m", "--mbr", help="Parse Master Boot Record Only", default=False, action="store_true")
        parser.add_argument("-p", "--partition", help="Select the partition number (from 1 to 4) for which you would like to retrieve the boot sector information.", default=False)
        parser.add_argument("-v", "--VERBOSE", help="Be VERBOSE and print out more information", default=False, action="store_true")
        parser.add_argument("-c", "--csv", help="Path to CSV file with SD card data blocks", required=False)
        parser.add_argument(
            "-l", "--loglevel",
            help="Set log level (DISABLED, ERROR, ALERT, WARNING, SUCCESS, INFO, VERBOSE)",
            default="INFO",
            choices=["DISABLED", "ERROR", "ALERT", "WARNING", "SUCCESS", "INFO", "VERBOSE"]
        )
        args = parser.parse_args()
        current_log_level = LogLevel[args.loglevel]
        # If CSV is provided, process it
        if args.csv:
            process_csv_and_feed_blocks(args, current_log_level)
        elif args.image:
            process_image(args, current_log_level)



    except KeyboardInterrupt:
        print("\n")
        print("[-] ^C The program has been INTERRUPTED !")

    except FileNotFoundError:
        print_message(f"No such file or directory '{args.image}'", 'ALERT') 

    except Exception as e:
        print("[-] " + str(e))
        traceback.print_exc()



# ============================================================== disk.py =============================================================


# ----------------------------------------- #
# Analysis of the Master Boot Record - MBR  #
# ----------------------------------------- #

class Disk:
    def __init__(self):
        self.partitions = []  # Store Partition objects
        self.info_mbr : dict = {}  # Dictionary to hold additional information if needed


    def parse_MBR(self, image, current_log_level = LogLevel.INFO, compare_to = None):  
        # Define table headers
        headers = ["", "Bootable", "Start Head", "Start Sector", "Start Cylinder", "File System", "End Head", "End Sector", "End Cylinder", "Start Sector (LBA)", "Number of Sectors", "Size (KB)"]
        rows = []

        partition_counter = 0                  # Keeping track of how many partition has been parsed
        check = 0                              # Checking how many partition is bootable

        print_message("Starting Parsing Of Master Boot Record :", LogLevel.SUCCESS, current_log_level)
        print_message("--------------------------------------------", LogLevel.INFO, current_log_level)

        print_message("Bootstrap Code located in the first 446 bytes of the first 512-byte sector (MBR)", LogLevel.VERBOSE, current_log_level)
        print_docs("This area contains the code that is executed when the computer starts up. It is responsible for loading the operating system and is typically written by the operating system vendor.", "0-445", 446, current_log_level = current_log_level)
        print_message("", LogLevel.INFO, current_log_level)

        for partition_counter in range(4):
            partition_obj = Partition()
            if partition_obj.get_info_from_MBR(image, partition_counter, current_log_level):
                self.partitions.append(partition_obj)
                rows.append([
                    "Partition {}".format(partition_counter+1),
                    partition_obj.bootable,
                    "0x" + partition_obj.start_head,
                    "0x" + partition_obj.start_sector,
                    "0x" + partition_obj.start_cylinder,
                    partition_obj.file_sys,
                    "0x" + partition_obj.end_head,
                    "0x" + partition_obj.end_sector,
                    "0x" + partition_obj.end_cylinder,
                    partition_obj.start_sector_lba,
                    partition_obj.num_sectors,
                    partition_obj.size_kb
                ])
                if partition_obj.bootable == "Bootable":
                    check += 1
                self.info_mbr["Partition {}".format(partition_counter+1)] = {
                    "Bootable": partition_obj.bootable,
                    "Start Head": partition_obj.start_head,
                    "Start Sector": partition_obj.start_sector,
                    "Start Cylinder": partition_obj.start_cylinder,
                    "File System": partition_obj.file_sys,
                    "End Head": partition_obj.end_head,
                    "End Sector": partition_obj.end_sector,
                    "End Cylinder": partition_obj.end_cylinder,
                    "Start Sector (LBA)": partition_obj.start_sector_lba,
                    "Number of Sectors": partition_obj.num_sectors,
                    "Size (KB)": partition_obj.size_kb
                }

        print_message("", LogLevel.INFO, current_log_level)
        print_message("Boot signature: 0x{}".format(str(Disk.get_signature(image))), LogLevel.INFO, current_log_level)
        
        # Checking the boot signature value:
        if (Disk.get_signature(image) != PREDEFINED_VALUES["BootSectorSignature"]):
            print_message("The boot signature is invalid. It should be 0xAA55", LogLevel.ALERT, current_log_level)
        if (check != 0) :
            if (check == 1) :
                print_message("{} partition is Bootable".format(check), LogLevel.SUCCESS, current_log_level)
                print_message("{} partitions are NOT Bootable\n".format(partition_counter-check+1), LogLevel.SUCCESS, current_log_level)
            else:
                print_message("{} partitions are Bootable".format(check), LogLevel.SUCCESS, current_log_level)
                print_message("{} partitions are NOT Bootable\n".format(partition_counter-check+1), LogLevel.SUCCESS, current_log_level)
        else :
            print_message("None of the partitions is bootable.", LogLevel.WARNING, current_log_level)

        # Print the table manually
        col_widths = [max(len(str(row[i])) for row in ([headers] + rows)) for i in range(len(headers))]
        table_lines = []

        # Header
        header_line = " | ".join(str(headers[i]).ljust(col_widths[i]) for i in range(len(headers)))
        table_lines.append(header_line)
        table_lines.append("-+-".join('-' * col_widths[i] for i in range(len(headers))))

        # Rows
        for row in rows:
            table_lines.append(" | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(headers))))

        print_message("Partition table entries\n"+ "\n".join(table_lines), LogLevel.SUCCESS, current_log_level)

        print_message("", LogLevel.INFO, current_log_level)

    @staticmethod
    def get_signature(hex_image):
        little_endian = hex_image[-4:]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value


#============================================== partition.py ============================================================
# Filesystems:
FILE_SYSTEMS = {
    "01": "FAT12",
    "04": "FAT16",
    "05": "MS Extended partition using CHS",
    "06": "FAT16B",
    "07": "NTFS, HPFS, exFAT",
    "0B": "FAT32 CHS",
    "0C": "FAT32 LBA",
    "0E": "FAT16 LBA",
    "0F": "MS Extended partition LBA",
    "42": "Windows Dynamic Volume",
    "82": "Linux Swap",
    "83": "Linux Native File System (ext2/3/4, JFS, Reiser, xiafs, and others)",
    "84": "Windows Hibernation Partition",
    "85": "Linux Extended",
    "8E": "Linux LVM",
    "A5": "FreeBSD Slice",
    "A6": "OpenBSD Slice",
    "AB": "Mac OS X boot",
    "AF": "HFS, HFS+",
    "EE": "MS GPT",
    "EF": "Intel EFI",
    "FB": "VMware VMFS",
    "FC": "VMware Swap",
    }

class Partition:
    def __init__(self) -> None:
        self.index: Optional[int] = None
        self.bootable: Optional[str] = None
        self.start_head: Optional[str] = None
        self.start_sector: Optional[str] = None
        self.start_cylinder: Optional[str] = None
        self.file_system: Optional[str] = None
        self.end_head: Optional[str] = None
        self.end_sector: Optional[str] = None
        self.end_cylinder: Optional[str] = None
        self.start_sector_lba: Optional[int] = None
        self.num_sectors: Optional[int] = None
        self.size_kb: Optional[int] = None

        self.table: Optional[str] = None
        self.FAT_file_system: Optional[FATFileSystem] = None
        self.info_boot_sector : dict = {}

    def get_info_from_MBR(self, image, partition_counter, current_log_level):
        start = 446 + partition_counter * PARTITION_TABLES_LENGTH * 2
        self.index = partition_counter

        self.bootable = self.get_bootable(image, partition_counter)
        self.start_head = self.get_starting_sector_CHS(image, partition_counter)[0:2]
        self.start_sector = self.get_starting_sector_CHS(image, partition_counter)[2:4]
        self.start_cylinder = self.get_starting_sector_CHS(image, partition_counter)[4:6]
        self.file_sys = self.get_file_sys(image, partition_counter)
        self.end_head = self.get_ending_sector_CHS(image, partition_counter)[0:2]
        self.end_sector = self.get_ending_sector_CHS(image, partition_counter)[2:4]
        self.end_cylinder = self.get_ending_sector_CHS(image, partition_counter)[4:6]
        self.start_sector_lba = self.get_starting_sector_LBA(image, partition_counter)
        self.num_sectors = int(self.get_total_sectors(image, partition_counter), 16)
        self.size_kb = round(self.num_sectors * 512 / 1024)


        if self.bootable == "NOT Bootable" and self.num_sectors == 0:
            print_message("Partition {} is not defined or has no sectors.".format(partition_counter+1), LogLevel.INFO, current_log_level)
            return False

        # Create a simple text table for this partition
        self.table = (
            f"+{'-'*14}+{'-'*14}+{'-'*12}+{'-'*14}+{'-'*16}+{'-'*16}+{'-'*10}+{'-'*12}+{'-'*14}+{'-'*20}+{'-'*19}+{'-'*12}+\n"
            f"| {'':12} | {'Bootable':12} | {'Start Head':10} | {'Start Sector':12} | {'Start Cylinder':14} | {'File System':14} | {'End Head':8} | {'End Sector':10} | {'End Cylinder':12} | {'Start Sector (LBA)':18} | {'Number of Sectors':17} | {'Size (KB)':10} |\n"
            f"+{'-'*14}+{'-'*14}+{'-'*12}+{'-'*14}+{'-'*16}+{'-'*16}+{'-'*10}+{'-'*12}+{'-'*14}+{'-'*20}+{'-'*19}+{'-'*12}+\n"
            f"| {'Partition '+str(partition_counter+1):12} | {self.bootable:12} | 0x{self.start_head:8} | 0x{self.start_sector:10} | 0x{self.start_cylinder:12} | {self.file_sys:14} | 0x{self.end_head:6} | 0x{self.end_sector:8} | 0x{self.end_cylinder:10} | {self.start_sector_lba:18} | {self.num_sectors:17} | {self.size_kb:10} |\n"
            f"+{'-'*14}+{'-'*14}+{'-'*12}+{'-'*14}+{'-'*16}+{'-'*16}+{'-'*10}+{'-'*12}+{'-'*14}+{'-'*20}+{'-'*19}+{'-'*12}+"
        )

        print_message("==> Partition n°" + str(partition_counter+1), LogLevel.INFO, current_log_level)
        if self.bootable == "Bootable":
            print_message("Bootable Flag: 0x80 => Partition {} is Bootable".format(str(partition_counter+1)), LogLevel.INFO, current_log_level)
        elif self.bootable == "NOT Bootable":
            print_message("Bootable Flag: 0x00 => Partition {} is NOT Bootable".format(str(partition_counter+1)), LogLevel.INFO, current_log_level)
        else: # Checking the get_bootable flag:
            print_message(f'The Bootable Flag value is invalid !!', LogLevel.ALERT, current_log_level)

        print_docs("Only two values are allowed: 0x80 means that the partition is get_bootable & 0x00 means that the partition is not bootable.", f"{str(start)}-{str(start)}", 1, current_log_level = current_log_level)
        print_message("Start Head: 0x{}".format(self.start_head), LogLevel.INFO, current_log_level)

        print_docs("The head number specifies which of the disk's platters the sector is located on", f"{str(start+1)}-{str(start+1)}", 1, current_log_level = current_log_level)
        print_message("Start Sector: 0x{}".format(self.start_sector), LogLevel.INFO, current_log_level)

        print_docs("The sector number specifies which sector on the track the partition begins.", f"{str(start+2)}-{str(start+2)}", 1, current_log_level = current_log_level)
        print_message("Start Cylinder: 0x{}".format(self.start_cylinder), LogLevel.INFO, current_log_level)

        print_docs("The cylinder number specifies which cylinder the partition begins on.", f"{str(start+3)}-{str(start+3)}", 1, current_log_level = current_log_level)
        print_message("File System: {}".format(self.file_sys), LogLevel.INFO, current_log_level)

        print_docs("The partition type field identifies the file system type that should be in the partition.", f"{str(start+4)}-{str(start+4)}", 1, current_log_level = current_log_level)
        print_message("End Head: 0x{}".format(self.end_head), LogLevel.INFO, current_log_level)

        print_docs("The ending head value indicates the head number of the last sector in the partition.", f"{str(start+5)}-{str(start+5)}", 1, current_log_level = current_log_level)
        print_message("End Sector: 0x{}".format(self.end_sector), LogLevel.INFO, current_log_level)

        print_docs("The ending sector value represents the sector number of the last sector in the partition.", f"{str(start+6)}-{str(start+6)}", 1, current_log_level = current_log_level)
        print_message("End Cylinder: 0x{}".format(self.end_cylinder), LogLevel.INFO, current_log_level)

        print_docs("The ending cylinder value represents the cylinder number of the last sector in the partition", f"{str(start+7)}-{str(start+7)}", 1, current_log_level = current_log_level)
        print_message("The starting sector of partition {}: {}".format(partition_counter+1, str(self.start_sector_lba)), LogLevel.INFO, current_log_level)

        print_docs("A 32-bit value that specifies the first sector of the partition relative to the beginning of the disk.", f"{str(start+8)}-{str(start+11)}", 4, current_log_level = current_log_level)
        print_message("Partition {} contains {} sector".format(partition_counter+1, str(self.num_sectors)), LogLevel.INFO, current_log_level)
        print_message("Partition size: {} Bytes ≃ {} KB\n".format(str(self.num_sectors*512), self.size_kb), LogLevel.INFO, current_log_level)

        print_docs("A 32-bit value that specifies the size of the partition in sectors.", f"{str(start+12)}-{str(start+15)}", 4, current_log_level = current_log_level)
        

        print_message("Partition Table Entry #{}".format(partition_counter+1) + '\n' + str(self.table), LogLevel.INFO, current_log_level)
        print_message("", LogLevel.INFO, current_log_level)

        return True
    


    def parseBootSector(self, hex_image, current_log_level = LogLevel.INFO):
        print_message("===> Boot Sector of pratition {} is located at: 0x{}".format(str(self.index + 1),str(self.start_sector_lba * 512)), LogLevel.INFO, current_log_level)
        # Only parse FAT file systems
        if self.file_sys and "FAT" in self.file_sys:
            self.FAT_file_system = FATFileSystem()
            self.FAT_file_system.parse_boot_sector(hex_image, self.index, current_log_level)
            # Store parsed boot sector info from the FATFileSystem instance
            if self.FAT_file_system:
                self.info_boot_sector = {
                    "jump_code": self.FAT_file_system.jump_code,
                    "oem": self.FAT_file_system.oem,
                    "bytes_per_sector": self.FAT_file_system.bytes_per_sector,
                    "sectors_per_cluster": self.FAT_file_system.sectors_per_cluster,
                    "reserved_area": self.FAT_file_system.reserved_area,
                    "num_of_fat": self.FAT_file_system.num_of_fat,
                    "num_of_root_dir_entries": self.FAT_file_system.num_of_root_dir_entries,
                    "num_of_sectors": self.FAT_file_system.num_of_sectors,
                    "media_type": self.FAT_file_system.media_type,
                    "fat_size": self.FAT_file_system.fat_size,
                    "num_of_sectors_per_track": self.FAT_file_system.num_of_sectors_per_track,
                    "num_of_heads": self.FAT_file_system.num_of_heads,
                    "num_of_hidden_sectors": self.FAT_file_system.num_of_hidden_sectors,
                    "total_number_of_sectors": self.FAT_file_system.total_number_of_sectors,
                    "num_of_sectors_per_fat": self.FAT_file_system.num_of_sectors_per_fat,
                    "flags": self.FAT_file_system.flags,
                    "fat32_version": self.FAT_file_system.fat32_version,
                    "root_dir_cluster_number": self.FAT_file_system.root_dir_cluster_number,
                    "fsinfo_sector_number": self.FAT_file_system.fsinfo_sector_number,
                    "backup_boot_sector": self.FAT_file_system.backup_boot_sector,
                    "bios_drive_number": self.FAT_file_system.bios_drive_number,
                    "extended_boot_signature": self.FAT_file_system.extended_boot_signature,
                    "partition_serial_number": self.FAT_file_system.partition_serial_number,
                    "volume_name": self.FAT_file_system.volume_name,
                    "file_system_type": self.FAT_file_system.file_system_type,
                    "boot_record_signature_1": self.FAT_file_system.boot_record_signature_1
                }


    @staticmethod
    def get_bootable(hex_image, partition_counter):
        if hex_image[MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter:MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+2] == "80" :
            return "Bootable"
        elif hex_image[MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter:MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+2] == "00" : 
            return "NOT Bootable"
        else:
            return "NOT Defined"

    @staticmethod
    def get_starting_sector_CHS(hex_image, partition_counter):
        return hex_image[MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+2:MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+8]

    @staticmethod
    def get_file_sys(hex_image, partition_counter):
        for key in FILE_SYSTEMS:
            if (str(hex_image[MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+8:MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+10]) == str(key).lower()) :
                return FILE_SYSTEMS[key]
        return "Unknown (0x" + str(hex_image[MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+8:MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+10]) + ")"

    @staticmethod
    def get_ending_sector_CHS(hex_image, partition_counter):
        return hex_image[MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+10:MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+16]

    @staticmethod
    def get_starting_sector_LBA(hex_image, partition_counter):
        # Start Sector value in little endian format
        hex_value = hex_image[MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+16:MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+24]
        # Convert to big endian format and remove leading zeros
        start_sector = bytes.fromhex(hex_value)
        start_sector = start_sector[::-1].hex().lstrip('0')
        # Add a zero if the result is an empty string
        if not start_sector:
            start_sector = '0'
        return int(start_sector, 16)

    @staticmethod
    def get_total_sectors(hex_image, partition_counter):
        hex_value = hex_image[MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+24:MASTER_BOOT_CODE_LENGTH*2+PARTITION_TABLES_LENGTH*2*partition_counter+32]
        total_sectors = bytes.fromhex(hex_value)
        total_sectors = total_sectors[::-1].hex().lstrip('0')
        if not total_sectors:
            total_sectors = '0'
        return total_sectors



# ================================================== FAT_file_system.py ========================================================


class FATFileSystem:
    def __init__(self):
        self.jump_code: Optional[str] = None
        self.oem: Optional[str] = None
        self.bytes_per_sector: Optional[int] = None
        self.sectors_per_cluster: Optional[int] = None
        self.reserved_area: Optional[int] = None
        self.num_of_fat: Optional[int] = None
        self.num_of_root_dir_entries: Optional[int] = None
        self.num_of_sectors: Optional[int] = None
        self.media_type: Optional[str] = None
        self.fat_size: Optional[int] = None
        self.num_of_sectors_per_track: Optional[int] = None
        self.num_of_heads: Optional[int] = None
        self.num_of_hidden_sectors: Optional[int] = None
        self.total_number_of_sectors: Optional[int] = None
        self.num_of_sectors_per_fat: Optional[int] = None
        self.flags: Optional[str] = None
        self.fat32_version: Optional[int] = None
        self.root_dir_cluster_number: Optional[int] = None
        self.fsinfo_sector_number: Optional[int] = None
        self.backup_boot_sector: Optional[int] = None
        self.bios_drive_number: Optional[int] = None
        self.extended_boot_signature: Optional[str] = None
        self.partition_serial_number: Optional[int] = None
        self.volume_name: Optional[str] = None
        self.file_system_type: Optional[str] = None
        self.boot_record_signature_1: Optional[str] = None
        
        self.root_dir = Optional[DirectoryEntry]  # Initialize root directory entry
        self.info_fsinfo : dict = {}
        self.info_fat : dict = {}

    def parse_boot_sector(self, image, partition_number, current_log_level=LogLevel.INFO):
        # Gather all BPB info as variables first, using function names minus 'get_'
        self.jump_code = FATFileSystem.get_jump_code(image)
        self.oem = FATFileSystem.get_oem(image)
        self.bytes_per_sector = FATFileSystem.get_bytes_per_sector(image)
        self.sectors_per_cluster = FATFileSystem.get_sectors_per_cluster(image)
        self.reserved_area = FATFileSystem.get_reserved_area(image)
        self.num_of_fat = FATFileSystem.get_num_of_fat(image)
        self.num_of_root_dir_entries = FATFileSystem.get_num_of_root_dir_entries(image)
        self.num_of_sectors = FATFileSystem.get_num_of_sectors(image)
        self.media_type = FATFileSystem.get_media_type(image)
        self.fat_size = FATFileSystem.get_fat_size(image)
        self.num_of_sectors_per_track = FATFileSystem.get_num_of_sectors_per_track(image)
        self.num_of_heads = FATFileSystem.get_num_of_heads(image)
        self.num_of_hidden_sectors = FATFileSystem.get_num_of_hidden_sectors(image)
        self.total_number_of_sectors = FATFileSystem.get_total_number_of_sectors(image)
        self.num_of_sectors_per_fat = FATFileSystem.get_num_of_sectors_per_fat(image)
        self.flags = FATFileSystem.get_flags(image)
        self.fat32_version = FATFileSystem.get_fat32_version(image)
        self.root_dir_cluster_number = FATFileSystem.get_root_dir_cluster_number(image)
        self.fsinfo_sector_number = FATFileSystem.get_fsinfo_sector_number(image)
        self.backup_boot_sector = FATFileSystem.get_backup_boot_sector(image)
        self.bios_drive_number = FATFileSystem.get_bios_drive_number(image)
        self.extended_boot_signature = FATFileSystem.get_extended_boot_signature(image)
        self.partition_serial_number = FATFileSystem.get_partition_serial_number(image)
        self.volume_name = FATFileSystem.get_volume_name(image)
        self.file_system_type = FATFileSystem.get_file_system_type(image)
        self.boot_record_signature_1 = FATFileSystem.get_boot_record_signature_1(image)

        # Now do the prints (with validation and docs)
        print_message("Parsing Boot Sector of Partition {} :".format(str(partition_number+1)), LogLevel.SUCCESS, current_log_level)
        print_message("---------------------------------------\n", LogLevel.INFO, current_log_level)

        # Jump Code
        print_message("Jump Code Instructions: 0x{}".format(str(self.jump_code)), LogLevel.INFO, current_log_level)
        print_docs("Assembly instruction to jump to boot code: JMP + NOP.", "0-2", 3, "no", LogLevel.VERBOSE, current_log_level)

        # OEM Name
        print_message("OEM Name: {}".format(self.oem), LogLevel.INFO, current_log_level)
        print_docs("OEM Name+version in Ascii.", "3-10", 8, "no", LogLevel.VERBOSE, current_log_level)

        # Bytes per sector
        print_message("The size of each sector in bytes: {}".format(str(self.bytes_per_sector)), LogLevel.INFO, current_log_level)
        if self.bytes_per_sector not in PREDEFINED_VALUES["BytesPerSector"]:
            print("\t", end="")
            print_message('This sector size value is invalid !!', LogLevel.WARNING, current_log_level)
        print_docs("Allowed values include 512, 1024, 2048, 4096.", "11-12", 2, "yes", LogLevel.VERBOSE, current_log_level)

        # Sectors per cluster
        print_message("Number of Sectors Per cluster: {}".format(str(self.sectors_per_cluster)), LogLevel.INFO, current_log_level)
        if self.sectors_per_cluster not in PREDEFINED_VALUES["SectorsPerCluster"]:
            print("\t", end="")
            print_message('The number of sectors per cluster is invalid !!', LogLevel.WARNING, current_log_level)
        print_docs("Allowed values are powers of 2, but the cluster size must be 32KB or smaller.", "13-13", 1, "yes", LogLevel.VERBOSE, current_log_level)

        # Cluster size
        cluster_size = self.sectors_per_cluster * self.bytes_per_sector
        print_message("The size of each Cluster in Bytes: {}".format(str(cluster_size)), LogLevel.INFO, current_log_level)
        if cluster_size > 32768:
            print("\t", end="")
            print_message('This cluster size is invalid !! It should be lesser than or equal to 32KB (KiloBytes)', LogLevel.WARNING, current_log_level)

        # Reserved area
        print_message("Number of Reserved Sectors: {}".format(str(self.reserved_area)), LogLevel.INFO, current_log_level)
        if self.reserved_area < PREDEFINED_VALUES["ReservedSectors"]:
            print("\t", end="")
            print_message('The number of reserved sectors is invalid !! It should be greater than or equal to 32', LogLevel.WARNING, current_log_level)
        print_docs("Size in sectors of the reserved area. FAT32 uses 32 reserved sector.", "14-15", 2, "yes", LogLevel.VERBOSE, current_log_level)

        # Number of root directory entries
        print_message("Number of Root Directory Entries: {}".format(str(self.num_of_root_dir_entries)), LogLevel.INFO, current_log_level)
        if self.num_of_root_dir_entries != PREDEFINED_VALUES["NrRootDirEntries"]:
            print("\t", end='')
            print_message('The number of root directory entries is invalid !! It should be equal to 0, by default', LogLevel.WARNING, current_log_level)
        print_docs("This is, by default, 0 for FAT32 and typically 512 for FAT16.", "17-18", 2, "yes", LogLevel.VERBOSE, current_log_level)

        # Total number of sectors (16-bit)
        print_message("Total number of sectors in the filesystem: {}".format(str(self.num_of_sectors)), LogLevel.INFO, current_log_level)
        if self.num_of_sectors != PREDEFINED_VALUES["SectorsPerFilesystem"]:
            print("\t", end='')
            print_message('The total number of sectors is invalid !! It should be equal to 0, by default', LogLevel.WARNING, current_log_level)
        print_docs("If the number of sectors is larger than can be represented in this 2-byte value, a 4-byte value exists later in the data structure and this should be 0.", "19-20", 2, "yes", LogLevel.VERBOSE, current_log_level)

        # Media type
        print_message("Media Descriptor Type: 0x{}".format(str(self.media_type)), LogLevel.INFO, current_log_level)
        if str(self.media_type) not in PREDEFINED_VALUES["MediaType"]:
            print("\t", end='')
            print_message('The media descriptor type is invalid !!', LogLevel.WARNING, current_log_level)
        print_docs("According to the Microsoft documentation, 0xf8 should be used for fixed disks and 0xf0 for removable", "21-21", 1, "no", LogLevel.VERBOSE, current_log_level)

        # Number of sectors per FAT (16-bit)
        print_message("Number of sectors Per FAT: {}".format(str(self.fat_size)), LogLevel.INFO, current_log_level)
        if self.fat_size != PREDEFINED_VALUES["SectorsPerFat"]:
            print("\t", end='')
            print_message('The number of sectors per FAT is invalid !! It should be 0, by default', LogLevel.WARNING, current_log_level)
        print_docs("16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0 by default", "22-23", 2, "yes", LogLevel.VERBOSE, current_log_level)

        # Number of sectors per track
        print_message("Number of sectors Per Track: {}".format(str(self.num_of_sectors_per_track)), LogLevel.INFO, current_log_level)
        print_docs("Sectors per track of storage device.", "24-25", 2, "no", LogLevel.VERBOSE, current_log_level)

        # Number of heads
        print_message("Number of Heads: {}".format(str(self.num_of_heads)), LogLevel.INFO, current_log_level)
        print_docs("Number of heads in storage device.", "26-27", 2, "no", LogLevel.VERBOSE, current_log_level)

        # Number of hidden sectors
        print_message("Number of Hidden Sectors: {}".format(str(self.num_of_hidden_sectors)), LogLevel.INFO, current_log_level)
        print_docs("Hidden sectors are sectors preceding the start of partition.", "28-31", 4, "no", LogLevel.VERBOSE, current_log_level)

        # Total number of sectors (32-bit)
        print_message("Total number of sectors in the filesystem (Second value): {}".format(str(self.total_number_of_sectors)), LogLevel.INFO, current_log_level)
        print_docs("32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0.", "32-35", 4, "yes", LogLevel.VERBOSE, current_log_level)

        # Number of sectors per FAT (32-bit)
        print_message("Number of Sectors Per FAT (Second Value): {}".format(str(self.num_of_sectors_per_fat)), LogLevel.INFO, current_log_level)
        print_docs("32-bit size in sectors of one File Allocation Table 'FAT'", "36-39", 2, "yes", LogLevel.VERBOSE, current_log_level)

        # Mirror Flags
        flags_str = str(self.flags)
        print_message("Mirror Flags: " + flags_str, LogLevel.INFO, current_log_level)
        print_docs("If bit 7 is 1, only one of the FAT structures is active and its index is described in bits 0–3. Otherwise, all FAT structures are mirrors of each other.", "40-41", 4, "yes", LogLevel.VERBOSE, current_log_level)

        # Filesystem Version
        print_message("Filesystem Version: {}".format(str(self.fat32_version)), LogLevel.INFO, current_log_level)
        print_docs("The major and minor version number => High Byte = Major Version, Low Byte = Minor Version", "42-43", 2, "yes", LogLevel.VERBOSE, current_log_level)

        # First cluster of root directory
        print_message("First cluster of root directory: {}".format(str(self.root_dir_cluster_number)), LogLevel.INFO, current_log_level)
        print_docs("Cluster where root directory can be found. Usually 2.", "44-47", 4, "yes", LogLevel.VERBOSE, current_log_level)

        # FSINFO sector number
        print_message("Sector Number of Filesystem Information (FSINFO): {}".format(str(self.fsinfo_sector_number)), LogLevel.INFO, current_log_level)
        print_docs("Sector where FSINFO structure can be found. Usually 1.", "48-49", 2, "no", LogLevel.VERBOSE, current_log_level)

        # Backup boot sector
        print_message("Sector Number of Boot Sector Backup Copy: {}".format(str(self.backup_boot_sector)), LogLevel.INFO, current_log_level)
        print_docs("Sector where backup copy of boot sector is located. (Default is 6)", "50-51", 2, "no", LogLevel.VERBOSE, current_log_level)

        # Skipping 12 bytes of reserved area
        print_docs("RESERVED", "52-63", "no", 12, LogLevel.VERBOSE, current_log_level)

        # BIOS drive number
        print_message("BIOS INT13h drive number: {}".format(str(self.bios_drive_number)), LogLevel.INFO, current_log_level)
        print_docs("Logical Drive Number ofPartition. Usually 0 or 0x80", "64-64", 1, "no", LogLevel.VERBOSE, current_log_level)

        # Skipping 1 unused byte
        print_docs("NOT USED. Used to be Current Head (used by Windows NT)", "65-65", 1, "no", LogLevel.VERBOSE, current_log_level)

        # Extended boot signature
        print_message("Extended Boot Signature: 0x{}".format(str(self.extended_boot_signature)), LogLevel.INFO, current_log_level)
        if str(self.extended_boot_signature) != PREDEFINED_VALUES["ExtendedBootSignature"]:
            print("\t", end='')
            print_message('The extended boot signature is invalid !! It should be 0x29, by default', LogLevel.WARNING, current_log_level)
        print_docs("Extended boot signature to identify if the next three values are valid. Default is 0x29", "66-66", 1, "no", LogLevel.VERBOSE, current_log_level)

        # Partition serial number
        print_message("Serial Number of the Partition: {}".format(str(self.partition_serial_number)), LogLevel.INFO, current_log_level)
        print_docs("Volume serial number, which some versions of Windows will calculate based on the creation date and time.", "67-70", 4, "no", LogLevel.VERBOSE, current_log_level)

        # Volume name
        print_message("Volume name of the Partition: {}".format(self.volume_name), LogLevel.INFO, current_log_level)
        print_docs("Volume label in ASCII. The user chooses this value when creating the file system.", "71-81", 11, "no", LogLevel.VERBOSE, current_log_level)

        # Filesystem type label
        print_message("Filesystem Type Label: {}".format(self.file_system_type), LogLevel.INFO, current_log_level)
        if PREDEFINED_VALUES["FileSystemLabel"] not in self.file_system_type:
            print("\t", end='')
            print_message('The file system label may be invalid !! It should be FAT32 but nothing is required, by default', LogLevel.WARNING, current_log_level)
        print_docs("File system type label in ASCII. Standard values include 'FAT32', but nothing is required.", "72-89", 8, "no", LogLevel.VERBOSE, current_log_level)

        # Skipping 420 bytes of executable code
        print_docs("NOT USED.", "90–509", 420, "no", LogLevel.VERBOSE, current_log_level)

        # Boot sector signature
        print_message("Boot Sector Signature: 0x{}".format(str(self.boot_record_signature_1).upper()), LogLevel.INFO, current_log_level)
        if self.boot_record_signature_1 != PREDEFINED_VALUES["BootSectorSignature"]:
            print("\t", end='')
            print_message('The boot sector signature is invalid !! It should be 0xAA55, by default', LogLevel.ALERT, current_log_level)
        print_docs("Signature value. Default is 0xAA55", "510-511", 2, "no", LogLevel.VERBOSE, current_log_level)

        print_message("", LogLevel.INFO, current_log_level)



    def parseFat(self, image, current_log_level=LogLevel.INFO):
        """
        Parses the FAT table and prints the entries.
        """
        print_message("This is a FAT Table of Partition {} :".format(str(1)), LogLevel.SUCCESS, current_log_level)
        print_message("---------------------------------------", LogLevel.INFO, current_log_level)
        
        print_message("FAT Table Entries (hex, color-coded):", LogLevel.INFO)
        for i in range(0, len(image), 8):  # 4 bytes per FAT32 entry, 8 hex chars
            entry_hex = image[i:i+8]
            # Convert from little endian to big endian
            entry_bytes = bytes.fromhex(entry_hex)
            entry_big_endian = entry_bytes[::-1].hex()
            if entry_big_endian[1:8] == '0' * 7:
                continue
            print_message(f"Entry 0x{i//8:06X}: 0x{entry_big_endian[1:8]}" , LogLevel.INFO, current_log_level)
            self.info_fat[f"Entry 0x{i//8:06X}"] = entry_big_endian[1:8]

        print_message("", LogLevel.INFO, current_log_level)



    def parse_FSINFO(self, image, key, current_log_level=LogLevel.INFO):
        print_message("Parsing FSINFO of Partition {} :".format(str(key)), LogLevel.SUCCESS, current_log_level)  
        print("---------------------------------------")
        print_message("First FSINFO Signature: 0x{}".format(str(FATFileSystem.get_fsinfo_signature_1(image))), LogLevel.INFO)     # 0x41615252 
        
        # Checking the first fsinfo signature value:
        if FATFileSystem.get_fsinfo_signature_1(image) != PREDEFINED_VALUES["FSINFO_Signature1"] :
            print("\t", end='')
            print_message(f'The first FSINFO signature may be invalid !! It should be 0x41615252, but nothing is required', LogLevel.WARNING, current_log_level)
        print_docs("FSINFO first signature. Default is 0x41615252.", "0-3", 4, "no", current_log_level=current_log_level)
        # .... SKIPPING 480 Bytes UNUSED .... #
        print_docs("NOT USED.", "5-483", 480, "no", current_log_level=current_log_level)
        print_message("Second FSINFO Signature: 0x{}".format(str(FATFileSystem.get_fsinfo_signature_2(image))), LogLevel.INFO)    # 0x61417272 
        
        # Checking the second fsinfo signature value:
        if FATFileSystem.get_fsinfo_signature_2(image) != PREDEFINED_VALUES["FSINFO_Signature2"] :
            print("\t", end='')
            print_message(f'The second FSINFO signature may be invalid !! It should be 0x61417272, but nothing is required', LogLevel.WARNING, current_log_level)
        print_docs("FSINFO second signature. Default is 0x61417272.", "484-487", 4, "no", current_log_level=current_log_level)
        print_message("Number of free clusters: {}".format(str(FATFileSystem.get_num_of_free_clusters(image))), LogLevel.INFO)           # 1084620
        print_docs("This one is set to 1 if unkown.", "488-491", 4, "no", current_log_level=current_log_level)  
        print_message("Sector number of the next free cluster: {}".format(str(FATFileSystem.get_next_free_cluster_sector_number(image))), LogLevel.INFO)  # 3
        print_docs("Cluster Number of Cluster that was Most Recently Allocated.", "492-495", 4, "no", current_log_level=current_log_level)  
        # .... SKIPPING 12 Bytes RESERVED .... #
        print_docs("NOT USED", "496-507", 12, "no", current_log_level=current_log_level)
        print_message("FSINFO Sector Signature: 0x{}".format(str(FATFileSystem.get_fsinfo_sector_signature(image)).upper()), LogLevel.INFO)      # 0xAA550000
        
        # Checking the fsinfo sector signature value:
        if FATFileSystem.get_fsinfo_sector_signature(image) != PREDEFINED_VALUES["FSINFOSector_Signature"] :
            print("\t", end='')
            print_message(f'The FSINFO sector signature is invalid !! It should be 0xAA550000', LogLevel.WARNING, current_log_level)
        print_docs("Signature. Default is 0xAA550000", "508-511", 4, "no", current_log_level=current_log_level)
        print_message("", LogLevel.INFO, current_log_level)


    def parse_root_directory(self, image, current_log_level=LogLevel.INFO):
        # Create a Directory object
        self.root_dir = DirectoryEntry()
        self.root_dir.filename = "Root"
        self.root_dir.parse_directory(image, current_log_level)

    def parse_directory(self, image, current_log_level=LogLevel.INFO):
        # Create a Directory object
        dir = DirectoryEntry()
        dir.parse_directory(image, current_log_level)

    @staticmethod
    def get_jump_code(hex_image):
        little_endian = hex_image[BOOT_SECTOR_START:BOOT_SECTOR_START+3*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value

    @staticmethod
    def get_oem(hex_image):
        jump_code = 3*2
        hex_bytes = bytes.fromhex(hex_image[BOOT_SECTOR_START+jump_code:BOOT_SECTOR_START+jump_code+8*2])
        return hex_bytes.decode('ascii')

    @staticmethod
    def get_bytes_per_sector(hex_image):
        start = 11*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_sectors_per_cluster(hex_image):
        start = 13*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+1*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_reserved_area(hex_image):
        start = 14*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_num_of_fat(hex_image):
        start = 16*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+1*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_num_of_root_dir_entries(hex_image):
        start = 17*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_num_of_sectors(hex_image):
        start = 19*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_media_type(hex_image):
        start = 21*2
        value = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+1*2]
        return value

    @staticmethod
    def get_fat_size(hex_image):
        start = 22*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_num_of_sectors_per_track(hex_image):
        start = 24*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_num_of_heads(hex_image):
        start = 26*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_num_of_hidden_sectors(hex_image):
        start = 28*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_total_number_of_sectors(hex_image):
        start = 32*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_num_of_sectors_per_fat(hex_image):
        start = 36*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_flags(hex_image):
        start = 40*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        hex_value = big_endian[::-1].hex()
        int_value = int(hex_value, 16)
        bits = format(int_value, '0{}b'.format(len(hex_value)*4))
        pretty_bits = ' '.join(bits[i:i+4] for i in range(0, len(bits), 4))
        return pretty_bits

    @staticmethod
    def get_fat32_version(hex_image):
        start = 42*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_root_dir_cluster_number(hex_image):
        start = 44*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_fsinfo_sector_number(hex_image):
        start = 48*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_backup_boot_sector(hex_image):
        start = 50*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_bios_drive_number(hex_image):
        start = 64*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+1*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_extended_boot_signature(hex_image):
        start = 66*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+1*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value

    @staticmethod
    def get_partition_serial_number(hex_image):
        start = 67*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    @staticmethod
    def get_volume_name(hex_image):
        start = 71*2
        hex_bytes = bytes.fromhex(hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+11*2])
        return hex_bytes.decode('ascii')

    @staticmethod
    def get_file_system_type(hex_image):
        start = 82*2
        hex_bytes = bytes.fromhex(hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+8*2])
        return hex_bytes.decode('ascii')

    @staticmethod
    def get_boot_record_signature_1(hex_image):
        start = 510*2
        little_endian = hex_image[BOOT_SECTOR_START+start:BOOT_SECTOR_START+start+2*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value




    # --------------------------------------------------- #
    # Analysis of File System Information Sector (FSINFO) #
    # --------------------------------------------------- #

    @staticmethod
    def get_fsinfo_signature_1(hex_image):
        # Size: 4 bytes 
        little_endian = hex_image[FSINFO_SECTOR_START:FSINFO_SECTOR_START+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value

    # .... SKIPPING UNUSED 480 Bytes ....

    @staticmethod
    def get_fsinfo_signature_2(hex_image):
        # Size: 4 bytes 
        start = 484*2           # This is the unused 480 bytes we skipped earlier + FirstSignature
        little_endian = hex_image[FSINFO_SECTOR_START+start:FSINFO_SECTOR_START+start+4*2] 
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value

    @staticmethod
    def get_num_of_free_clusters(hex_image): 
        # Size: 4 bytes
        start = 488*2           # FirstSignature + 480 + SecondSignature
        little_endian = hex_image[FSINFO_SECTOR_START+start:FSINFO_SECTOR_START+start+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)   # Set to 1 if unknown number

    @staticmethod
    def get_next_free_cluster_sector_number(hex_image): 
        # Size: 4 bytes
        start = 492*2           # FirstSignature + 480 + SecondSignature + NumberOfFreeClusters
        little_endian = hex_image[FSINFO_SECTOR_START+start:FSINFO_SECTOR_START+start+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    # .... SKIPPING UNUSED 12 Bytes ....

    @staticmethod
    def get_fsinfo_sector_signature(hex_image):
        # Size: 4 bytes
        start = 508*2           # FirstSignature + 480 + SecondSignature + NumberOfFreeClusters + NextFreeClusterSectorNumber + 12 
        little_endian = hex_image[FSINFO_SECTOR_START+start:FSINFO_SECTOR_START+start+4*2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value  # Apply Some checks here !!
    

# ================================================= directory.py =========================================================
ENTRY_ATTRIBUTES = {
   "ATTR_READ_ONLY": 0x01,
   "ATTR_HIDDEN": 0x02,
   "ATTR_SYSTEM": 0x04,
   "ATTR_VOLUME_ID": 0x08,
   "ATTR_DIRECTORY": 0x10,
   "ATTR_ARCHIVE": 0x20,
   "ATTR_LONG_NAME": 0x0F  # (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID)
}


class DirectoryEntry:

    def __init__(self):
        self.filename: Optional[str] = None
        self.attr: Optional[str] = None
        self.size: Optional[int] = None
        self.first_cluster: Optional[int] = None
        self.created: Optional[str] = None
        self.modified: Optional[str] = None
        self.last_access: Optional[str] = None

        self.children: list[DirectoryEntry] = []  # List to hold child directories
        self.info : dict = {}  # Dictionary to hold additional information if needed



    def parse_directory_entry(self, entry_bytes, current_log_level = LogLevel.INFO):
    
        DIR_Name = entry_bytes[0:11]
        DIR_Attr = entry_bytes[11]
        DIR_CrtTime = int.from_bytes(entry_bytes[14:16], 'little')
        DIR_CrtDate = int.from_bytes(entry_bytes[16:18], 'little')
        DIR_LstAccDate = int.from_bytes(entry_bytes[18:20], 'little')
        DIR_FstClusHI = int.from_bytes(entry_bytes[20:22], 'little')
        DIR_WrtTime = int.from_bytes(entry_bytes[22:24], 'little')
        DIR_WrtDate = int.from_bytes(entry_bytes[24:26], 'little')
        DIR_FstClusLO = int.from_bytes(entry_bytes[26:28], 'little')
        DIR_FileSize = int.from_bytes(entry_bytes[28:32], 'little')

        # Check for free/unused entry
        if DIR_Name[0] in (0x00, 0xE5):
            return False

        # Format file name
        name = DIR_Name[:8].decode('ascii', errors='replace').rstrip()
        ext = DIR_Name[8:11].decode('ascii', errors='replace').rstrip()
        if ext:
            filename = f"{name}.{ext}"
        else:
            filename = name

        # Attribute string
        attr_flags = []
        if DIR_Attr & ENTRY_ATTRIBUTES["ATTR_READ_ONLY"]:
            attr_flags.append("R")
        if DIR_Attr & ENTRY_ATTRIBUTES["ATTR_HIDDEN"]:
            attr_flags.append("H")
        if DIR_Attr & ENTRY_ATTRIBUTES["ATTR_SYSTEM"]:
            attr_flags.append("S")
        if DIR_Attr & ENTRY_ATTRIBUTES["ATTR_VOLUME_ID"]:
            attr_flags.append("V")
        if DIR_Attr & ENTRY_ATTRIBUTES["ATTR_DIRECTORY"]:
            attr_flags.append("D")
        if DIR_Attr & ENTRY_ATTRIBUTES["ATTR_ARCHIVE"]:
            attr_flags.append("A")
        attr_str = "".join(attr_flags)

        # Set instance variables
        self.filename = filename
        self.attr = attr_str
        self.size = DIR_FileSize
        self.first_cluster = ((DIR_FstClusHI << 16) | DIR_FstClusLO)
        self.created = f"{DirectoryEntry.decode_date(DIR_CrtDate)} {DirectoryEntry.decode_time(DIR_CrtTime)}"
        self.modified = f"{DirectoryEntry.decode_date(DIR_WrtDate)} {DirectoryEntry.decode_time(DIR_WrtTime)}"
        self.last_access = DirectoryEntry.decode_date(DIR_LstAccDate)

        # Print directory entry info using print_message

        print_message(f"Directory Entry:", LogLevel.INFO, current_log_level)
        print_message(f"  Name: {self.filename}", LogLevel.INFO, current_log_level)
        print_message(f"  Attr: {self.attr}", LogLevel.VERBOSE, current_log_level)
        print_message(f"  Size: {self.size} bytes", LogLevel.VERBOSE, current_log_level)
        print_message(f"  First Cluster: {self.first_cluster}", LogLevel.VERBOSE, current_log_level)
        print_message(f"  Created: {self.created}", LogLevel.VERBOSE, current_log_level)
        print_message(f"  Modified: {self.modified}", LogLevel.VERBOSE, current_log_level)
        print_message(f"  Last Access: {self.last_access}", LogLevel.VERBOSE, current_log_level)
        print_message("", LogLevel.VERBOSE, current_log_level)
        return True

    def parse_directory(self, image, current_log_level = LogLevel.INFO):
        if self.filename is None:
            self.filename = "Error"
        # Removed Fore and Style usage
        print_message("Parsing " + self.filename + " Directory", LogLevel.SUCCESS, current_log_level)
        print("---------------------------------------")

        for entry_number in range(0, SECTOR_SIZE//32):
            dir = DirectoryEntry()  # Create a new Directory instance for each entry
            start = entry_number * 32*2

            # Parse fields from entry (hex string to bytes)
            entry_bytes = bytes.fromhex(image[start:start+32*2])
            print_message(f"Parsing entry {entry_number + 1} the bytes are: {entry_bytes.hex()}", LogLevel.VERBOSE, current_log_level)
            dir.parse_directory_entry(entry_bytes, current_log_level)
            if not dir.filename:  # If the entry is empty, skip it
                continue
            self.children.append(dir)  # Add the directory entry to the children list

            self.info[entry_number] = {
                "filename": dir.filename,
                "attr": dir.attr,
                "size": dir.size,
                "first_cluster": dir.first_cluster,
                "created": dir.created,
                "modified": dir.modified,
                "last_access": dir.last_access
            }
        print_message("", LogLevel.INFO, current_log_level)
    # --------------------------------------------------- #
    # Analysis of the directory entries #
    # --------------------------------------------------- #
    @staticmethod
    def get_directory_entry(hex_image, sector_number, entry_number, sectors_per_cluster, current_log_level = LogLevel.INFO):
        start = 2 * SECTOR_SIZE * sector_number * sectors_per_cluster + entry_number * 32*2
        print_message("start: "+  str(start), LogLevel.VERBOSE, current_log_level)
        end = start + 32*2
        if hex_image[start:end] == "":
            print_message("empty", LogLevel.VERBOSE, current_log_level)
        return(hex_image[start:end])
    

    # Decode date/time helpers
    @staticmethod
    def decode_date(val):
        year = ((val >> 9) & 0x7F) + 1980
        month = (val >> 5) & 0x0F
        day = val & 0x1F
        return f"{year:04d}-{month:02d}-{day:02d}"
    
    @staticmethod
    def decode_time(val):
        hour = (val >> 11) & 0x1F
        minute = (val >> 5) & 0x3F
        second = (val & 0x1F) * 2
        return f"{hour:02d}:{minute:02d}:{second:02d}"
