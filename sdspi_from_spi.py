"""
High Level Analyzer script for interpreting SDSPI communication.

This is supported by Saleae Logic v2.3.1 or later.

For more information, see https://github.com/saleae/logic2-examples

Authors: Paul de La Sayette, Jash Gujarathi

Forked from the original script by Tim Kostka :
https://github.com/timkostka/saleae_sdmmc_from_spi

"""

## imports 
from saleae.data.timing import GraphTimeDelta
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame
#from common import gvars

EXPECT_DATA = 11


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
    8: ("SEND_EXT_CSD", 1),
    9: ("SEND_CSD", 2),
    10: ("SEND_CID", 2),
    11: ("obsolete", None),
    12: ("STOP_TRANSMISSION", 1),
    13: ("SEND_STATUS", 1),
    14: ("BUSTEST_R", 1),
    15: ("GO_INACTIVE_STATE", None),
    19: ("BUSTEST_W", 1),
    # Block-oriented read commands (class 2)
    16: ("SET_BLOCKLEN", 1),
    17: ("READ_SINGLE_BLOCK", EXPECT_DATA),
    18: ("READ_MULTIPLE_BLOCK", EXPECT_DATA ),
    21: ("SEND_TUNING_BLOCK", EXPECT_DATA ),
    # Class 3 commands
    20: ("obsolete", None),
    22: ("reserved", None),
    # Block-oriented write commands (class 4)
    23: ("SET_BLOCK_COUNT", 1),
    24: ("WRITE_BLOCK", EXPECT_DATA),
    25: ("WRITE_MULTIPLE_BLOCK", EXPECT_DATA),
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

}


def get_response_length(resp):
    """Return the length of the given response type."""
    if resp == 1:
        return 8
    elif resp == 5:
        return 16
    elif resp == 10:
        return 515*8
    elif resp == 2:
        return 136
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
    in_idle_state = bits[7]
    info = "R1"
    #info += str(bits[0:11])
    if in_idle_state:
        info += ", IDLE"
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
    """Return a string description from the response 2 bits."""
    assert len(bits) == 136
    return r"R2, CID or CSD"
    okay = True
    start_bit = bits[0]
    transmission_bit = bits[1]
    command_index = value_from_bits(bits[2:8])
    device_status = bits[8:40]
    crc7 = value_from_bits(bits[40:47])
    end_bit = value_from_bits(bits[47:48])
    if start_bit or transmission_bit or not end_bit:
        okay = False
    current_state = value_from_bits(device_status[19:23])
    info = "R1, "
    if current_state in CURRENT_STATE:
        info += CURRENT_STATE[current_state]
    else:
        info += "UNKNOWN (%d)" % current_state
        okay = False
    if not okay:
        info += ", ERROR"
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
                         Idle State (1)
                         R/W Data (8 bits)
    """

    assert len(bits) == 16
    start_bit = bits[0]
    parameter_err = bits[1]
    function_err = bits[3]
    crc_err = bits[4]
    ill_command_err = bits[5]
    is_idle_state = bits[7]
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
    if is_idle_state:
        info += ",IDLE_STATE "
    else:
        info += ",NOT_IDLE "
    info += ",{} ".format(rw_data)
    return info


class SdioState:

    def __init__(self):
        # bits leftover for the next command or response
        self.command_bits_mosi= None
        self.command_bits_miso = None
        # start_time of the start of the command bits
        self.command_start_mosi = None
        self.command_start_miso = None
        # value used during debugging
        self.debug = None
        # time of first value
        self.first_time_mosi = None
        self.first_time_miso = None
        # response number expected, or None
        self.expected_response = None
        # bits in the expected response
        self.expected_response_length = 48
        print("\n\n\n\n\n")

    # to do : find a way to avoid duplicated code for MOSI and MISO
    # for example : create 2 different classes for mosi and miso communication 

    def add_mosi_byte(self, value, start_time, end_time):
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
        if (value == 255 ) and not self.command_bits_mosi:
            return None
        if not self.first_time_mosi:
            self.first_time_mosi = start_time
        new_bits = bits_from_byte(value)
        bit_length = GraphTimeDelta(float(end_time - start_time) / 7.5)
        # self.debug = "t %s to %s" % (start_time, end_time)
        self.debug = "start_time:%s, end_time:%s" % (start_time, end_time)
        # if we're expecting a response, look for one
        # self.debug = "start %g" % (end_time - start_time)
        # start_time -= bit_length * 1.5
        # start_time -= 1e-7

        # start of new command
        if not self.command_bits_mosi:
            count = 0
            while new_bits[0] and self.expected_response != 10:
                count += 1
                del new_bits[0]
            self.command_start_mosi = start_time + GraphTimeDelta(count * float(bit_length))
            self.command_bits_mosi = new_bits
            return None
        # add bits to command
        self.command_bits_mosi += new_bits
        # if not enough to complete a command, just return
        #self.expected_response_length = 48
        if len(self.command_bits_mosi) < self.expected_response_length:
            return None
        # if we reached this point, we have a response or a command
        this_response_length = self.expected_response_length
        this_response_type = self.expected_response
        # get end time of this
        command_start_mosi = self.command_start_mosi
        command_end = end_time - GraphTimeDelta(float(bit_length) * (
            len(self.command_bits_mosi) - this_response_length
        ))
        bits = self.command_bits_mosi[:this_response_length]
        print("\n")
        print("mosi bits : " + bin(value_from_bits(bits)))
        # determine if response or command
        transmission_bit = bits[1]
        first_byte = bits[0:8]
        if first_byte == [1, 1, 1, 1, 1, 1, 0, 0]:
            data  = interpret_data_block(bits)

        elif first_byte == [1, 1, 1, 1, 1, 1, 0, 1]:
            data  = interpret_data_block(bits)

        elif first_byte == [1, 1, 1, 1, 1, 1, 1 ,0]:
            data  = interpret_data_block(bits)
            self.expected_response = None
            self.expected_response_length = 48

        elif transmission_bit:
            data = interpret_command(bits)
            command_index = value_from_bits(bits[2:8])
            # if a command, set up the next expected response
            self.expected_response = get_command_response(command_index)
            self.expected_response_length = get_response_length(
                self.expected_response
            )
        else:
            self.expected_response = None
            self.expected_response_length = 48
            print("Unknown response type")
            data = "R%s" % this_response_type
           
        print("returned data : "+ data)
        print(
            "start=%s, duration=%s"
            % (command_start_mosi, command_end - command_start_mosi)
        )
        return_data = {
            "command_start": command_start_mosi,
            "command_end": command_end,
            "data": data,
        }
        self.command_bits_mosi = None
        return return_data
    
    
    def add_miso_byte(self, value, start_time, end_time):
        """
        Add a byte of data and return a command, or None.

        start is the start time of the byte
        end is the end time of the byte

        """
        #if no expected response, ignore value
        if not self.expected_response:
            return None
        # this code could be improved to be more reliable, it sometimes bugs at startup
        if isinstance(value, bytes):
            assert len(value) == 1
            value = value[0]
        assert isinstance(value, int)
        # if bus is idle, ignore value
        if (value == 255 ) and not self.command_bits_miso :
            return None
        if not self.first_time_miso:
            self.first_time_miso = start_time
        new_bits = bits_from_byte(value)
        bit_length = GraphTimeDelta(float(end_time - start_time) / 7.5)
        # self.debug = "t %s to %s" % (start_time, end_time)
        self.debug = "start_time:%s, end_time:%s" % (start_time, end_time)
        # if we're expecting a response, look for one
        # self.debug = "start %g" % (end_time - start_time)
        # start_time -= bit_length * 1.5
        # start_time -= 1e-7

        # start of new command
        if not self.command_bits_miso:
            count = 0
            while new_bits[0] and self.expected_response != 10:
                count += 1
                del new_bits[0]
            self.command_start_miso = start_time + GraphTimeDelta(count * float(bit_length))
            self.command_bits_miso = new_bits
            return None
        # add bits to command
        self.command_bits_miso += new_bits
        # if not enough to complete a command, just return
        #self.expected_response_length = 48
        if len(self.command_bits_miso) < self.expected_response_length:
            return None
        # if we reached this point, we have a response or a command
        this_response_length = self.expected_response_length
        this_response_type = self.expected_response
        # get end time of this
        command_start_miso = self.command_start_miso
        command_end = end_time - GraphTimeDelta(float(bit_length) * (
            len(self.command_bits_miso) - this_response_length
        ))
        bits = self.command_bits_miso[:this_response_length]
        print("\n")
        print("miso bits : " + bin(value_from_bits(bits)))
        # determine if response or command
        transmission_bit = bits[1]
        first_byte = bits[0:8]
        if 0 and first_byte == [1, 1, 1, 1, 1, 1, 0, 0]:
            data  = interpret_data_block(bits)

        elif 0 and first_byte == [1, 1, 1, 1, 1, 1, 0, 1]:
            data  = interpret_data_block(bits)

        elif this_response_type == 10 or (0 and first_byte == [1, 1, 1, 1, 1, 1, 1 ,0]):
            data  = interpret_data_block(bits)
            self.expected_response = None
            self.expected_response_length = 48
        else:
            self.expected_response = None
            self.expected_response_length = 48
            if this_response_type == 1 or this_response_type is None:
                data = interpret_response1(bits)
            elif this_response_type == 2:
                data = interpret_response2(bits)
            elif this_response_type == 3:
                data = interpret_response3(bits)
            elif this_response_type == 5:
                data = interpret_response5(bits)
            elif this_response_type == 11:
                    data = interpret_response1(bits)
                    self.expected_response = 10
                    self.expected_response_length = 515*8
            else:
                print("Unknown response type")
                data = "R%s" % this_response_type

        print("returned data : " + data)
        print(
            "start=%s, duration=%s"
            % (command_start_miso, command_end - command_start_miso)
        )
        return_data = {
            "command_start": command_start_miso,
            "command_end": command_end,
            "data": data,
        }
        self.command_bits_miso = None
        return return_data
    

class SdmmcFromSpiAnalyzer(HighLevelAnalyzer):
    # class to communicate with the analyzer using the API

    last_end_time = None

    result_types = {
        "error": {"format": "ERROR"},
        "sdio": {"format": "{{data.info}}"},
    }

    def __init__(self):
        self.state = SdioState()

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
            if not((value_mosi == 255 ) and not self.state.command_bits_mosi):
                mosi_data = self.state.add_mosi_byte(value_mosi, data.start_time, data.end_time)
                

        if "miso" in data.data:
            value_miso = data.data["miso"]
            if isinstance(value_miso, bytes):
                assert len(value_miso) == 1
                value_miso = value_miso[0]
            assert isinstance(value_miso, int)
            # if bus is idle, ignore value
            if not((value_miso == 255 ) and not self.state.command_bits_miso):
                miso_data = self.state.add_miso_byte(value_miso, data.start_time, data.end_time)
                

            
        
        if mosi_data:
            #mosi_data["command_start"] = mosi_data["command_end"]
            data = {
                "start_time": mosi_data["command_start"],
                "end_time": mosi_data["command_end"],
                "mosi_data": mosi_data["data"],
                "miso_data" : "",
            }
        elif miso_data: 
            #miso_data["command_start"] = miso_data["command_end"] 
            data = {
                "start_time": miso_data["command_start"],
               "end_time": miso_data["command_end"],
               "mosi_data": "",
              "miso_data" : miso_data["data"],
            }
        elif mosi_data and miso_data:
            # not sure what to do here, but it shouldn't happen
            print("ERROR: both mosi and miso data")
            data = {
                "start_time": mosi_data["command_start"],
                "end_time": mosi_data["command_end"],
                "mosi_data": mosi_data["data"] + "error",
                "miso_data" : miso_data["data"] + "error",
            }
        else:
            return None
        

        if self.last_end_time is not None:
            print("last_end_time = %s, data[start_time] = %s" % (self.last_end_time, data["start_time"]))
            if data["start_time"] <= self.last_end_time:
                print("ERROR: overlapping frames")
                print("last_end_time = %s, data[start_time] = %s" % (self.last_end_time, data["start_time"]))
                print("mosi_data = %s" % data["mosi_data"])
                print("miso_data = %s" % data["miso_data"])
                data["start_time"] = self.last_end_time + GraphTimeDelta(1e-6)
                # this usally creates an error when it's exectued
                # to do : find a way to not enter in the if statement


        self.last_end_time = data["end_time"]
        return AnalyzerFrame(
            'SD frame',
            data["start_time"],
            data["end_time"],
            {"mosi_data": data["mosi_data"],
            "miso_data": data["miso_data"]}
            #to do : have better visualtion of the data
        )
