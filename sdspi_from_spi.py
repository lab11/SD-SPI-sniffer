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
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame



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
    1: ("SEND_OP_COND", 3),
    2: ("ALL_SEND_CID", 2),
    3: ("SET_RELATIVE_ADDR", 1),
    4: ("SET_DSR", None),
    5: ("SLEEP_AWAKE", 1),
    6: ("SWITCH", 1),
    7: ("SELECT_CARD", 1),
    8: ("SEND_IF_COND", 7),
    9: ("SEND_CSD", 2),
    10: ("SEND_CID", 2),
    11: ("obsolete", None),
    12: ("STOP_TRANSMISSION", 1),
    13: ("SEND_STATUS", 2),
    14: ("BUSTEST_R", 1),
    15: ("GO_INACTIVE_STATE", None),
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
    39: ("FAST_IO", 4),
    40: ("GO_IRQ_STATE", 5),
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
    assert len(bits) == 48, "bits length is %d, bits are %s, " %(len(bits), hex(sum([(bits[i]==True)*2**(len(bits)-i) for i in range(len(bits))])))
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
    info += hex(sum([(bits[i+8]==True)*2**(data_block_size-i) for i in range(data_block_size)]))

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
    # value used during debugging
    debug = print

    def __init__(self):
        # bits leftover for the next command or response
        self.message_bits= None
        # start_time of the start of the command bits
        self.message_start = None
        # end time of the command bits
        self.message_end = None
        # time of first value
        self.first_time = None
        print("\n\n\n")

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
            print("\033[33mWarning : byte received is %s but no message expected, byte is discarded\033[0m" % hex(value))
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
            # add bits to command
            self.message_bits += new_bits

        # if we don't have enough bits, return None
        if len(self.message_bits) < dataLineState.expected_message_length:
            return None
        
        # if we reached this point, we have a response or a command
        this_message_length = dataLineState.expected_message_length
        dataLineState.this_message_type = dataLineState.expected_message_type

        # get end time of this message
        self.message_end = end_time - GraphTimeDelta(float(bit_length) * (
            len(self.message_bits) - this_message_length
        ))
        bits = self.message_bits[:this_message_length]
        print("\n")

        data = self.interpret_message(bits)

        #print the data in binary if small, in hex otherwise
        if len(bits)<= 136:
            print("bits (bin): "+ bin(value_from_bits(bits)))
            print("bits (hex): "+ hex(value_from_bits(bits)))
        else:
            print("bits (hex): "+ hex(value_from_bits(bits)))
            pass
        

        hex_data = hex(value_from_bits(bits))
        ascii_data = ""
        for i in range(2, len(hex_data), 2):
            #print("hex data: "+ hex_data[i:i+2])
            # print the data ascii character
            if len(hex_data[i:i+2]) == 2:
                #print("ascii data: "+ chr(int(hex_data[i:i+2], 16)))
                ascii_data += chr(int(hex_data[i:i+2], 16))

        #replace spaces with a dot
        ascii_data = ascii_data.replace(" ", ".")
        print("Ascii data: " + ascii_data)

        print(
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

        print("\033[1mMOSI message\033[0m")
        # determine if response or command
        transmission_bit = bits[1]
        first_byte = bits[0:8]
        if dataLineState.this_message_type == 12 and  first_byte == [1, 1, 1, 1, 1, 1, 0, 0]:
            data  = interpret_data_block(bits)
            dataLineState.expected_message_type = None
            dataLineState.expected_message_length = 48
            print("\031[1mERROR, This is a multiple block write which is not yet implemented in this software\033[0m")

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
            print("Unknown response type")
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
        

        print("\033[1mMISO message\033[0m")
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
                print("Unknown response type")
                data = "R%s" % dataLineState.this_message_type

        return data
    
    def is_message_expected(self, value):
        if dataLineState.expected_message_type == 13 and value in [252, 253, 254]:
            return True
        return dataLineState.expected_message_type in [1,2,3,5,7,10,11]


class SdmmcFromSpiAnalyzer(HighLevelAnalyzer):
    # class to communicate with the analyzer using the API

    last_end_time = None

    result_types = {
        "error": {"format": "ERROR"},
        "sdio": {"format": "{{data.info}}"},
    }

    def __init__(self):
        self.mosi_state = mosiLineState()
        self.miso_state = misoLineState()


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

        return AnalyzerFrame(
            'SD frame',
            data["start_time"],
            data["end_time"],
            {"mosi_data": data["mosi_data"],
            "miso_data": data["miso_data"], "Ascii_data": data["Ascii_data"]}
            #to do : have better visualtion of the data
        )
