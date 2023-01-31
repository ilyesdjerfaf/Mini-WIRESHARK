from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from functools import partial
import utils_djerfaf_snaoui as utils


def get_frames(file_path):
    current_frame = ""
    frame = []
    with open(file_path, 'r') as file:

        for i in range(4):
            file.readline()

        while True:
            # Get next line from file
            line_i = file.readline()

            # if line is empty
            # end of file is reached
            if not line_i:
                break
            if line_i.startswith('Frame'):
                frame.append(current_frame)
                current_frame = ""
            else:
                current_frame += line_i

        frame.append(current_frame)
    return frame


def get_pertinent_infos(pertinent_info):
    output_pertinent = f"{pertinent_info[0]} : {pertinent_info[1]} ----------------------" \
                       f"----------------------------> {pertinent_info[2]}\n"
    if pertinent_info[0] == "ARP":
        fg_color = "#1E5128"
    elif pertinent_info[0] == "ICMP":
        fg_color = "#346751"
    elif pertinent_info[0] == "IGMP":
        fg_color = "#301B3F"
    elif pertinent_info[0] == "TCP":
        fg_color = "red"
        output_pertinent += f"{pertinent_info[3]}          {pertinent_info[5]}           {pertinent_info[4]} "
    elif pertinent_info[0] == "UDP":
        fg_color = "#090057"
        output_pertinent += f"{pertinent_info[3]}                                                           " \
                            f"          {pertinent_info[4]} "
    elif pertinent_info[0] == "ENCAP":
        fg_color = "#D65A31"
    elif pertinent_info[0] == "OSPF":
        fg_color = "#0D63A5"
    elif pertinent_info[0] == "SCTP":
        fg_color = "#52057B"
    else:
        fg_color = "#9F8772"
    return output_pertinent, fg_color


def display_frame_infos(frame_index: int):
    output.delete(1.0, END)
    output.insert(INSERT, frames_list[frame_index])


def ui(number_of_frames, file_path, pertinent):
    def filter_me():
        protocol_list = ['ARP', 'ICMP', 'IGMP',
                         'TCP', 'UDP', 'ENCAP', 'OSPF', 'SCTP']
        filter_request = filter_bar.get()
        if filter_request != "":
            for widgets in second_frame.winfo_children():
                widgets.destroy()
            
            # filter http 
            if filter_request=="http":
                for j in range(number_of_frames):
                    tp, fr = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'TCP' and (pertinent[j][3] == 80 or pertinent[j][4] == 80):
                        Button(second_frame, text=tp, width=100, height=2, fg=fr, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            
            # filter tcp
            if filter_request == "tcp":
                for j in range(number_of_frames):
                    tp, fr = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'TCP':
                        Button(second_frame, text=tp, width=100, height=2, fg=fr, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            
            # filter tcp
            if filter_request == "udp":
                for j in range(number_of_frames):
                    tp, fr = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'UDP':
                        Button(second_frame, text=tp, width=100, height=2, fg=fr, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return

            # filter of protocols
            if filter_request.startswith("protocol=="):
                proto = filter_request[10:]
                if proto.upper() in protocol_list:
                    for j in range(number_of_frames):
                        td, fc = get_pertinent_infos(pertinent[j])
                        if pertinent[j][0] == proto.upper():
                            Button(second_frame, text=td, width=100, height=2, fg=fc, command=partial(
                                display_frame_infos, j), ).pack(fill=BOTH, expand=True)

                    return
            if filter_request.startswith("protocol =="):
                proto = filter_request[11:]
                if proto.upper() in protocol_list:
                    for j in range(number_of_frames):
                        ti, fo = get_pertinent_infos(pertinent[j])
                        if pertinent[j][0] == proto.upper():
                            Button(second_frame, text=ti, width=100, height=2, fg=fo, command=partial(
                                display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                    return
            if filter_request.startswith("protocol == "):
                proto = filter_request[12:]
                if proto.upper() in protocol_list:
                    for j in range(number_of_frames):
                        ts, fl = get_pertinent_infos(pertinent[j])
                        if pertinent[j][0] == proto.upper():
                            Button(second_frame, text=ts, width=100, height=2, fg=fl, command=partial(
                                display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                    return
            # filter of tcp.port
            tcp_port = "&&&&&&&&''''"
            if filter_request.startswith("tcp.port=="):
                tcp_port = filter_request[10:]
            if filter_request.startswith("tcp.port =="):
                tcp_port = filter_request[11:]
            if filter_request.startswith("tcp.port == "):
                tcp_port = filter_request[12:]
            if tcp_port != "&&&&&&&&''''":
                try:
                    port_number = int(tcp_port)
                except:
                    return
                
                for j in range(number_of_frames):
                    tp, fr = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'TCP' and (pertinent[j][3] == port_number or pertinent[j][4] == port_number):
                        Button(second_frame, text=tp, width=100, height=2, fg=fr, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return

            # filter of tcp.scrport
            tcp_srcport = "&&&&&&&&''''"
            if filter_request.startswith("tcp.srcport=="):
                tcp_srcport = filter_request[13:]
            if filter_request.startswith("tcp.srcport =="):
                tcp_srcport = filter_request[14:]
            if filter_request.startswith("tcp.srcport == "):
                tcp_srcport = filter_request[15:]
            if tcp_srcport != "&&&&&&&&''''":
                try:
                    src_port_number = int(tcp_srcport)
                except:
                    return
                
                for j in range(number_of_frames):
                    ttd, ffc = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'TCP' and pertinent[j][3] == src_port_number:
                        Button(second_frame, text=ttd, width=100, height=2, fg=ffc, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return

            # filter of tcp.destport
            tcp_destport = "&&&&&&&&''''"
            if filter_request.startswith("tcp.destport=="):
                tcp_destport = filter_request[14:]
            if filter_request.startswith("tcp.destport =="):
                tcp_destport = filter_request[15:]
            if filter_request.startswith("tcp.destport == "):
                tcp_destport = filter_request[16:]
            if tcp_destport != "&&&&&&&&''''":
                try:
                    dest_port_number = int(tcp_destport)
                except:
                    return
                
                for j in range(number_of_frames):
                    tti, ffo = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'TCP' and pertinent[j][4] == dest_port_number:
                        Button(second_frame, text=tti, width=100, height=2, fg=ffo, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return

            # filter of udp.port
            udp_port = "&&&&&&&&''''"
            if filter_request.startswith("udp.port=="):
                udp_port = filter_request[10:]
            if filter_request.startswith("udp.port =="):
                udp_port = filter_request[11:]
            if filter_request.startswith("udp.port == "):
                udp_port = filter_request[12:]
            if udp_port != "&&&&&&&&''''":
                try:
                    port_number = int(udp_port)
                except:
                    return
                
                for j in range(number_of_frames):
                    tts, ffl = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'UDP' and (
                            pertinent[j][3] == port_number or pertinent[j][4] == port_number):
                        Button(second_frame, text=tts, width=100, height=2, fg=ffl, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            
            # filter of udp.scrport
            udp_srcport = "&&&&&&&&''''"
            if filter_request.startswith("udp.srcport=="):
                udp_srcport = filter_request[13:]
            if filter_request.startswith("udp.srcport =="):
                udp_srcport = filter_request[14:]
            if filter_request.startswith("udp.srcport == "):
                udp_srcport = filter_request[15:]
            if udp_srcport != "&&&&&&&&''''":
                try:
                    src_port_number = int(udp_srcport)
                except:
                    return
                
                for j in range(number_of_frames):
                    tty, ffr = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'UDP' and pertinent[j][3] == src_port_number:
                        Button(second_frame, text=tty, width=100, height=2, fg=ffr, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            
            # filter of udp.destport
            udp_destport = "&&&&&&&&''''"
            if filter_request.startswith("udp.destport=="):
                udp_destport = filter_request[14:]
            if filter_request.startswith("udp.destport =="):
                udp_destport = filter_request[15:]
            if filter_request.startswith("udp.destport == "):
                udp_destport = filter_request[16:]
            if udp_destport != "&&&&&&&&''''":
                dest_port_number = int(udp_destport)
                for j in range(number_of_frames):
                    ttx, ffg = get_pertinent_infos(pertinent[j])
                    if pertinent[j][0] == 'UDP' and pertinent[j][4] == dest_port_number:
                        Button(second_frame, text=ttx, width=100, height=2, fg=ffg, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            

            # filter of port
            port = "&&&&&&&&''''"
            if filter_request.startswith("port=="):
                port = filter_request[6:]
            if filter_request.startswith("port =="):
                port = filter_request[7:]
            if filter_request.startswith("port == "):
                port = filter_request[8:]
            if port != "&&&&&&&&''''":
                try:
                    port_num = int(port)
                except:
                    return
                
                for j in range(number_of_frames):
                    text_display, fg_color = get_pertinent_infos(
                        pertinent[j])
                    if (pertinent[j][0] == 'UDP' or pertinent[j][0] == 'TCP') and (
                            pertinent[j][3] == port_num or pertinent[j][4] == port_num):
                        Button(second_frame, text=text_display, width=100, height=2, fg=fg_color, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return

            # filter of scrport
            srcport = "&&&&&&&&''''"
            if filter_request.startswith("srcport=="):
                srcport = filter_request[9:]
            if filter_request.startswith("srcport =="):
                srcport = filter_request[10:]
            if filter_request.startswith("srcport == "):
                srcport = filter_request[11:]
            if srcport != "&&&&&&&&''''":
                try:
                    src_port = int(srcport)
                except:
                    return
                for j in range(number_of_frames):
                    text_display, fg_color = get_pertinent_infos(pertinent[j])
                    if (pertinent[j][0] == 'UDP' or pertinent[j][0] == 'TCP') and pertinent[j][3] == src_port:
                        Button(second_frame, text=text_display, width=100, height=2, fg=fg_color, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            
            # filter of destport
            destport = "&&&&&&&&''''"
            if filter_request.startswith("destport=="):
                destport = filter_request[10:]
            if filter_request.startswith("destport =="):
                destport = filter_request[11:]
            if filter_request.startswith("destport == "):
                destport = filter_request[12:]
            if destport != "&&&&&&&&''''":
                
                try:
                    dest_port = int(destport)
                except:
                    return
                for j in range(number_of_frames):
                    text_display, fg_color = get_pertinent_infos(pertinent[j])
                    if (pertinent[j][0] == 'UDP' or pertinent[j][0] == 'TCP') and pertinent[j][4] == dest_port:
                        Button(second_frame, text=text_display, width=100, height=2, fg=fg_color, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            

            # filter of IPs
            ips = "&&&&&&&&''''"
            if filter_request.startswith("ip=="):
                ips = filter_request[4:]
            if filter_request.startswith("ip =="):
                ips = filter_request[5:]
            if filter_request.startswith("ip == "):
                ips = filter_request[6:]
            if ips != "&&&&&&&&''''":
                for j in range(number_of_frames):
                    text_displaay, fg_coloor = get_pertinent_infos(pertinent[j])
                    if pertinent[j][1] == ips or pertinent[j][2] == ips:
                        Button(second_frame, text=text_displaay, width=100, height=2, fg=fg_coloor, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            

            # filter of source IPs
            src_ips = "&&&&&&&&''''"
            if filter_request.startswith("ip.src=="):
                src_ips = filter_request[8:]
            if filter_request.startswith("ip.src =="):
                src_ips = filter_request[9:]
            if filter_request.startswith("ip.src == "):
                src_ips = filter_request[10:]
            if src_ips != "&&&&&&&&''''":
                for j in range(number_of_frames):
                    text_displayyy, fg_colorrr = get_pertinent_infos(pertinent[j])
                    if pertinent[j][1] == src_ips:
                        Button(second_frame, text=text_displayyy, width=100, height=2, fg=fg_colorrr, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return
            
            dst_ips = "&&&&&&&&''''"
            # filter of destination IPs
            if filter_request.startswith("ip.dst=="):
                dst_ips = filter_request[8:]
            if filter_request.startswith("ip.dst =="):
                dst_ips = filter_request[9:]
            if filter_request.startswith("ip.dst == "):
                dst_ips = filter_request[10:]
            if dst_ips != "&&&&&&&&''''":
                for j in range(number_of_frames):
                    ttgt, fgfg = get_pertinent_infos(pertinent[j])
                    if pertinent[j][2] == dst_ips:
                        Button(second_frame, text=ttgt, width=100, height=2, fg=fgfg, command=partial(
                            display_frame_infos, j), ).pack(fill=BOTH, expand=True)
                return

    def reset_me():
        for widgets in second_frame.winfo_children():
            widgets.destroy()
        for ii in range(number_of_frames):
            text_displayy, fg_colorr = get_pertinent_infos(pertinent[ii])
            Button(second_frame, text=text_displayy, width=100, height=2, fg=fg_colorr,
                   command=partial(display_frame_infos, ii), ).pack(fill=BOTH, expand=True)

    global frames_list
    frames_list = get_frames(file_path)
    root = Tk()
    root.lift()
    root.title('Flow Graph++')
    root.geometry("700x700")
    root.resizable(False, False)

    # filter bar
    filter_bar = Entry(root, width=30, font=("Helvetica", 10))
    filter_bar.pack(padx=20, pady=5)
    filter_button = Button(root, text='Filter', command=filter_me)
    filter_button.pack()
    reset_button = Button(root, text='Reset', command=reset_me)
    reset_button.pack()

    # create a main frame
    main_frame = Frame(root)
    main_frame.pack(fill=BOTH, expand=1)

    # create a canvas
    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

    # add a scroll bar to the canvas
    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    # configure the canvas
    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    # create another frame inside the canvas
    second_frame = Frame(my_canvas)

    # add that new frame to a window in the canvas
    my_canvas.create_window((0, 0), window=second_frame, anchor='nw')

    global output
    output = Text(root, height=100, width=100)
    output.pack(fill=BOTH)

    for i in range(number_of_frames):
        text_display, fg_color = get_pertinent_infos(pertinent[i])
        Button(second_frame, text=text_display, width=100, height=2, fg=fg_color,
               command=partial(display_frame_infos, i), ).pack(fill=BOTH, expand=True)

    root.focus_force()
    root.mainloop()


def begin_analyse():
    filepath = read_valid_file()
    list_of_trams = utils.get_list_of_trams(filepath)
    number_of_frames = len(list_of_trams)
    counter = 1
    f = open("frameAnalyser.txt", "w")
    pertinent = []
    for tram in list_of_trams:
        pertinent.append(utils.analyse(tram, counter, f))
        counter += 1
    f.close()
    ui(number_of_frames, "frameAnalyser.txt", pertinent)


def read_valid_file():
    file = get_file()
    while not utils.is_well_formed(file):
        messagebox.showerror(
            'Analyse Error', 'Error: Your txt file contains error(s)!')
        file = get_file()
    return file


def get_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        parent=root, initialdir="/", title='Please select a file', filetypes=(('Text Files', '*.txt'),))
    root.destroy()
    return file_path


if __name__ == "__main__":
    begin_analyse()
