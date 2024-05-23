# 调用第三方库
import socket                # 导入socket模块，用于套接字操作
import time                  # 导入时间相关模块，提供处理时间的功能
from pysnmp.hlapi import *   # 从“pysnmp”这个库的“hlapi”子模块中导入所有的内容，“pysnmp”是用于实现简单网络管理协议（SNMP）相关操作的库。
from tkinter import Tk, Label, Entry, Button, Text, Listbox, Frame, LabelFrame   # 引入tkinter这个图形用户界面库，
# Tk：主窗口类，用于创建应用程序的主窗口。
# Label：标签控件，用于显示文本信息。
# Entry：输入框控件，允许用户输入文本。
# Button：按钮控件，可执行特定操作。
# Text：多行文本框控件。
# Listbox：列表框控件，可展示一列可选择的项。
# Frame：框架控件，用于对其他控件进行分组和布局。
# LabelFrame：带标签的框架控件，是一种特殊的框架。
import base64         # 引入base64模块，主要用于进行 base64 编码和解码操作。
import struct         # 引入结构化模块，主要用于处理结构化数据。
#  ---------------------------------------------------------------------------------------------------------------------
# 创建UDP套接字
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # 创建了套接字对象，
# socket.socket() 创建一个新的套接字。
# socket.AF_INET 表示使用 IPv4 地址族。
# socket.SOCK_DGRAM 表示创建的是数据报套接字（UDP 套接字）。
# ----------------------------------------------------------------------------------------------------------------------

query_history = []  # 创建了空列表，为后面存储查询历史
def query_snmp(oid):             # 定义了一个名为query_snmp的函数，参数为：oid。
    try:                        # 进行异常处理，没有异常，执行try里面的语句，有异常执行Exception后的语句
        # 发送 SNMP 查询
        errorIndication, errorStatus, errorIndex, varBinds = next(         # 使用生成器函数 next() 来获取一个迭代器中的下一个元素，并将其拆分成多个变量进行接收。
            getCmd(SnmpEngine(),          #
                   CommunityData('public'),  # 社区名
                   UdpTransportTarget(('127.0.0.1', 161)),  # 代理地址和端口
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)))
        )

        if errorIndication:
            result_text.insert("end", f"错误指示: {errorIndication}\n")
        elif errorStatus:
            result_text.insert("end", f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}\n")
        else:
            for varBind in varBinds:
                result_text.insert("end", f' = '.join([x.prettyPrint() for x in varBind]) + "\n")

        query_history.append(oid)  # 添加到查询历史
    except Exception as e:
        result_text.insert("end", f"发生异常: {e}\n")

def ber_encode(data):
    encoded_data = None

    if isinstance(data, int):
        encoded_data = struct.pack('>I', data)
    elif isinstance(data, str):
        encoded_data = str.encode(data)
    # 可以根据需要添加其他数据类型的处理

    return base64.b64encode(data)

def snmp_packet_constructor():
    # 版本
    version = 1
    # 社区名
    community = str.encode("public")
    # PDU 类型（这里假设是 GET 请求）
    pdu_type = 0
    # 请求 ID
    request_id = 1234
    # 错误状态
    error_status = 0
    # 错误索引
    error_index = 0

    # 构建 PDU 部分
    pdu = struct.pack(">BBH", pdu_type, error_status, request_id)

    # 构建整个报文
    packet = struct.pack(">B", version) + ber_encode(community) + pdu

    encoded_packet = ber_encode(packet)
    result_text.insert("end", f"构造的 SNMP 报文（BER 编码后）: {encoded_packet}\n")

    # 进一步扩展：显示详细的报文结构信息
    result_text.insert("end", f"版本: {version}\n")
    result_text.insert("end", f"社区名（BER 编码后）: {ber_encode(community)}\n")
    result_text.insert("end", f"PDU 部分: {pdu}\n")

def snmp_packet_parser(encoded_packet):
    try:
        decoded_packet = base64.b64decode(encoded_packet)

        # 提取版本
        version = struct.unpack(">B", decoded_packet[0:1])[0]
        # 提取社区名（BER 解码）
        community_length = struct.unpack(">B", decoded_packet[1:2])[0]
        community = decoded_packet[2:2 + community_length].decode()
        # 提取 PDU 部分
        pdu = decoded_packet[2 + community_length:]

        # 进一步解析 PDU 内容（根据实际需求）

        result_text.insert("end", f"解析的 SNMP 报文: 版本={version}, 社区={community}\n")

        # 显示更详细的解析信息
        result_text.insert("end", f"PDU 内容: {pdu}\n")
    except Exception as e:
        result_text.insert("end", f"解析报文时出错: {e}")

def on_query_button_click():
    oid = oid_entry.get()
    query_snmp(oid)

def show_history():
    history_listbox.delete(0, "end")
    for item in query_history:
        history_listbox.insert("end", item)

def handle_socket_receive():
    while True:
        data, addr = sock.recvfrom(1024)
        result_text.insert("end", f"接收到来自 {addr} 的数据: {data.decode()}\n")
        time.sleep(1)

# 创建主窗口
root = Tk()

# 主框架
main_frame = Frame(root)
main_frame.pack(fill="both", expand=True)

# 左侧区域
left_frame = Frame(main_frame)
left_frame.pack(side="left", fill="both", expand=True)

# 输入区域框架
input_frame = LabelFrame(left_frame, text="输入与操作")
input_frame.pack(fill="both", expand=True)

# 添加标签
label = Label(input_frame, text="输入 OID:")
label.pack()

# 添加输入框
oid_entry = Entry(input_frame)
oid_entry.pack()

# 添加查询按钮
query_button = Button(input_frame, text="查询", command=on_query_button_click)
query_button.pack()

# 添加结果文本框
result_text = Text(input_frame)
result_text.pack(fill="both", expand=True)

# 右侧区域
right_frame = Frame(main_frame)
right_frame.pack(side="right", fill="both", expand=True)

# 构造报文区域框架
construct_frame = LabelFrame(right_frame, text="SNMP 报文构造")
construct_frame.pack(fill="both", expand=True)

# 添加构造 SNMP 报文按钮
construct_button = Button(construct_frame, text="构造 SNMP 报文", command=snmp_packet_constructor)
construct_button.pack()

# 解析报文区域框架
parse_frame = LabelFrame(right_frame, text="SNMP 报文解析")
parse_frame.pack(fill="both", expand=True)

# 添加解析 SNMP 报文输入框和按钮
parse_entry = Entry(parse_frame)
parse_entry.pack()
parse_button = Button(parse_frame, text="解析 SNMP 报文", command=lambda: snmp_packet_parser(parse_entry.get()))
parse_button.pack()

# 添加查询历史列表框
history_listbox = Listbox(right_frame)
history_listbox.pack(fill="both", expand=True)

# 添加查看历史按钮
history_button = Button(right_frame, text="查看历史", command=show_history)
history_button.pack()

# 主事件循环
root.mainloop()

sock.close()