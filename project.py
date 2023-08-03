#########################################################################################################################################
#imports

from tkinter import filedialog
from tkinter import *
from tkinter import messagebox
import tkintermapview
from PIL import ImageTk, Image
import customtkinter
import os
from scapy import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP
import time
from datetime import datetime, timezone
import requests

#########################################################################################################################################

customtkinter.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

#########################################################################################################################################
#paths + images

image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "images")
pcap_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pcaps")
network_home_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "network3.png")), size=(612, 181))
attack_symbol = customtkinter.CTkImage(Image.open(os.path.join(image_path, "attack_symbol.png")), size=(50, 50))
home_symbol = customtkinter.CTkImage(Image.open(os.path.join(image_path, "home_symbol.png")), size=(40, 40))
prep_symbol = customtkinter.CTkImage(Image.open(os.path.join(image_path, "prep_symbol.png")), size=(40, 40))
analysis_symbol = customtkinter.CTkImage(Image.open(os.path.join(image_path, "analysis_symbol.png")), size=(40, 40))
map_symbol = customtkinter.CTkImage(Image.open(os.path.join(image_path, "map.png")), size=(40, 40))

#########################################################################################################################################
#get ip geolocation data

def get_location(ip):
    ip_address = ip
    response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()      #request ip data
    location_data = {                                                           #store data
        "ip": ip_address,
        "city": response.get("city"),
        "region": response.get("region"),
        "country": response.get("country_name"),
        "latitude": response.get("latitude"),
        "longitude": response.get("longitude")
    }

    return location_data["latitude"], location_data["longitude"]                #return latitude + longitude

#########################################################################################################################################
#convert epoch to localtime

def timestamp(ts_epoch):
    ts = datetime.fromtimestamp(ts_epoch).strftime('%Y-%m-%d %H:%M:%S')         #epoch -> standard
    return ts

#########################################################################################################################################
#process / analyse pcap file for ARP Poisoning Attack

def process_pcap_arp(file_name):
    net = {"192.168.100.2":"54:52:00:12:35:00","192.168.100.8":"08:00:27:72:e3:c1","192.168.100.3":"08:00:27:73:8e:fa","192.168.100.5":"08:00:27:ad:fc:da"}
    #dictionary of true ip_addr:mac_addr of machines on simulated network
    
    #net = {"192.168.1.1":"08:00:27:5e:01:7c","192.168.1.104":"08:00:27:b8:b7:58","192.168.1.105":"08:00:27:2d:f8:5a"}        
    #evaluation code - activate when using public arp pcap - eval-arp

    print('Analysing {}...'.format(file_name))  #Output to terminal - analysing in progress

#-------------------------------------------------------#
#initialise variables

    count = 0                           #packet counter          
    arp_pkt_counter = 0                 #arp packet counter
    attack = False                      #attack detected?
    first_pkt_timestamp = None       ####
    pkt_number = None                   #
    first_pkt_src = None                # (meta)data display variables
    first_pkt_smac = None               #
    first_pkt_dst = None                #
    first_pkt_dmac = None            ####

#-------------------------------------------------------#
#iterate through packets and analyse - look for arp poisoning, store necessary data

    truefileloc = os.path.join(pcap_path,file_name)                 #true file location - will therefore run regardless of cwd
    
    for (pkt_data,pkt_metadata) in RawPcapReader(truefileloc):      #iterate through each packet in pcap
        count+=1                                                    #packet counter

        ether_pkt = Ether(pkt_data)                                 #packet - ethernet frame
        if 'type' not in ether_pkt.fields:                          #disregard LLC frames
            continue

        if ether_pkt.type != 0x0806:                                #disregard non-ARP packets
            continue

        arp_pkt = ether_pkt[ARP]                                    #packet - ARP layer

        arp_pkt_counter+=1                                          #arp packet counter

        if arp_pkt_counter == 1:                                    #if 1st arp packet, store data - incase of non-attack, display first packet data
            detection = "No ARP Poisoning Detected\nDisplaying First ARP Data"  #detection status
            first_pkt_timestamp = timestamp(pkt_metadata.sec)                   #timestamp
            pkt_number = count                                                  #packet number
            first_pkt_src = ("Source IP: "+str(arp_pkt.psrc))                   #source ip
            first_pkt_smac = ("Source MAC: "+str(arp_pkt.hwsrc))                #source mac
            first_pkt_dst = ("Destination IP: "+str(arp_pkt.pdst))              #destination ip
            first_pkt_dmac = ("Destination MAC: "+str(arp_pkt.hwdst))           #destinaion mac

        try:
            if net[arp_pkt.psrc] != arp_pkt.hwsrc:                      #if mac != associated ip mac, arp poisoning detected - store data
                detection = "      ARP Poisoning Detected      "                    #detection
                first_pkt_timestamp = timestamp(pkt_metadata.sec)                   #timestamp
                pkt_number = count                                                  #packet number
                key = [k for k, v in net.items() if v == arp_pkt.hwsrc][0]          #find true source ip - use mac to find associated ip
                first_pkt_src = ("Attacker IP: "+str(key))                          #attacker ip
                first_pkt_smac = ("Attack MAC: "+str(arp_pkt.hwsrc))                #attacker mac
                first_pkt_dst = ("Target IP: "+str(arp_pkt.pdst))                   #target ip
                first_pkt_dmac = ("Target MAC: "+str(arp_pkt.hwdst))                #target mac
                attack = True                                                       #attack = True
                break                                                               #break out of loop, attack detected, save resources
        except:
            print("IP Unknown")

    return pkt_number, attack, first_pkt_src, first_pkt_smac, first_pkt_dst, first_pkt_dmac, first_pkt_timestamp, detection
        
#########################################################################################################################################
#process / analyse pcap file for SYN Attack

def process_pcap_syn(file_name):
    print('Analysing {}...'.format(file_name))  #Output to terminal - analysing in progress

#-------------------------------------------------------#
#initialise variables

    count = 0                               #packet counter
    ipv4_packet_count = 0                   #ipv4 packet counter
    syn = 0                                 #tcp syn flag counter
    attack = False                          #attack detected?
    first_atkpkt_timestamp = None        ####
    first_atkpkt_src = None                 #
    first_atkpkt_sport = None               #
    first_atkpkt_dst = None                 #
    first_atkpkt_dport = None               #
    first_atkpkt_protocol = None            #
    first_pkt_timestamp = None              # (meta)data display variables
    first_pkt_src = None                    #
    first_pkt_sport = None                  #
    first_pkt_dst = None                    #
    first_pkt_dport = None                  #
    first_pkt_protocol = None            ####

#-------------------------------------------------------#
#iterate through packets and analyse - look for syn attack, store necessary data

    truefileloc = os.path.join(pcap_path,file_name)                 #true file location - will therefore run regardless of cwd

    for (pkt_data, pkt_metadata) in RawPcapReader(truefileloc):     #iterate through each packet in pcap
        count += 1                                                  #packet counter

        ether_pkt = Ether(pkt_data)                                 #packet - ethernet frame
        if 'type' not in ether_pkt.fields:                          #disregard LLC frames
            continue

        if ether_pkt.type != 0x0800:                                #disregard non-ipv4 packets
            continue

        ip_pkt = ether_pkt[IP]                                      #packet - ip layer
        

        ipv4_packet_count+=1                                        #ipv4 packet counter

        if ipv4_packet_count == 1:                                  #if 1st ipv4 packet, store data - incase of non-attack, display first packet data
            first_pkt_timestamp = timestamp(pkt_metadata.sec)                                                   #timestamp
            first_pkt_src = ip_pkt.src                                                                          #source ip
            first_pkt_dst = ip_pkt.dst                                                                          #destination ip
            first_pkt_protocol = (str(ip_pkt.layers()[1]).strip("'><.")).lstrip("class 'scapy.layers.inet.")    #protocol
            

        if ip_pkt.proto != 6:                                       #disregard non-tcp packets
            # Ignore non-TCP packet
            continue
        
        tcp_pkt = ip_pkt[TCP]                                       #packet - tcp frame

        if ipv4_packet_count == 1:                                  #if 1st ipv4 packet, store data - incase of non-attack, can display first packet data
            first_pkt_sport = tcp_pkt.sport                         #source port
            first_pkt_dport = tcp_pkt.dport                         #destination port

        if str(tcp_pkt.flags) == 'S':                               #if syn flag
            syn+=1                                                  #start / continue adding to syn counter (searching for syn attack)
        else:                                                       #if not syn flag
            syn=0                                                   #reset counter

        if syn==1:                                                  #if first syn flag packet, store data - incase of attack, display first attack packet data
            first_atkpkt_no = count                                 #first attack packet number (allows for further analysis with other tools if desired, can quickly find start of attack in large pcap)
            first_atkpkt_timestamp = timestamp(pkt_metadata.sec)                                                    #timestamp
            first_atkpkt_src = ip_pkt.src                                                                           #source ip
            first_atkpkt_sport = ip_pkt[TCP].sport                                                                  #source port
            first_atkpkt_dst = ip_pkt.dst                                                                           #destination ip
            first_atkpkt_dport = ip_pkt[TCP].dport                                                                  #destination port
            first_atkpkt_protocol = (str(ip_pkt.layers()[1]).strip("'><")).lstrip("class 'scapy.layers.inet.")      #protocol

        if syn>2:                                                   #if syn counter > 2 (3 syn packets in a row)
            attack=True                                             #set attack to true
            break                                                   #attack found, break out of loop (save resources)
        
#-------------------------------------------------------#
#check attack status, return appropriate data

    if attack == True:                                              #if attack is true, return attack data
        detection = "SYN Attack Detected"                           
        src = str(first_atkpkt_src)+':'+str(first_atkpkt_sport)
        dest = str(first_atkpkt_dst)+':'+str(first_atkpkt_dport)
        return first_atkpkt_no, attack, src, dest, first_atkpkt_timestamp, first_atkpkt_protocol, detection
        

    if attack == False:                                             #if attack is not true, return first packet data
        detection = "No SYN Attack Detected"
        
        if first_pkt_sport != None:                                 #if port data is available, send ip+port data
            src = str(first_pkt_src)+':'+str(first_pkt_sport)
            dest = str(first_pkt_dst)+':'+str(first_pkt_dport)
            
        else:
            src = str(first_pkt_src)+'    '                         #if port data is not available, send ip data
            dest = str(first_pkt_dst)+'    '

        return count, attack, src, dest, first_pkt_timestamp, first_pkt_protocol, detection

#########################################################################################################################################
#changeframe function #1 - main frames

def changeframe(frame):         #take argument, i.e framename
    frame.tkraise()             #raise frame

#########################################################################################################################################
#changeframe function #2 - side frames

def changeframetest(frame):                                             #take argement- i.e framename
    if frame == "home":                                                 #if frame == ...
        home_frame.grid(column = 1, row=0, sticky = "nesw")             #grid (display) frame
    else:                                                               #if frame != ...
        home_frame.grid_forget()                                        #grid_forget (remove) frame
    if frame == "prep":                                                                 
        prep_frame.grid(column = 1, row=0, sticky = "nesw")                      #
    else:                                                                       # #
        prep_frame.grid_forget()                                               # # #
    if frame == "analysis":                                                      #
        analysis_frame.grid(column = 1, row=0, sticky = "nesw")                  #
    else:                                                                        #
        analysis_frame.grid_forget()                                             #
    if frame == "map":                                                           #
        map_frame.grid(column = 1, row=0, sticky= "nesw")                        #
    else:                                                                        #
        map_frame.grid_forget()                                                  #

#########################################################################################################################################
#import folder function / storage + attack selection storage

def importfolder():
    global filename                                                                     #pcap filename accessible globally
    file = filedialog.askopenfilename()                                                 #open, select, store pcap filename
    discard, sep, filename = file.partition('pcaps/')                                   #dissect and store filename - remove unnecessary filepath
    #print("Testing: File output -",filename)                                            #testing purposes - test case 03-05
    if filename == '':                                                                      #if filename empty
        import_success_label.configure(text ="Unsuccessful Import - No File Imported")          #display unsuccessful import to user
    else:                                                                                   #if filename not empty
        import_success_label.configure(text='{} Successfully Imported'.format(filename))        #display filename successfully imported to user

    import_success_label.grid(column=0, row=2, pady=40)                                             

def attackselection(selection):                                                         #optionmenu command, pass in selected option
    global atk_selection                                                                #attack selection accessible globally
    atk_selection = selection                                                           #store selected option
    #print("Attack Selected: ",atk_selection)                                            #testing purposes - test case 06

#########################################################################################################################################
#analyse button function

def analysis():

#-------------------------------------------------------#
#validation + attack selection

    try:                                                                                                    #validation #1 - check if an attack is selected, if no error - continue
        if atk_selection == "SYN Attack":                                                           #if attack selected is "SYN Attack"
            try:                                                                                            #validation #2 - check if a file is imported, if no error - continue
                pno, atk, src, dest, dt, prot, detection = process_pcap_syn(filename)               #process_pcap_syn function - pass in filename, store return variables
            except:                                                                                         #validation #2 - if error - display message box alerting user to import file
                messagebox.showerror('User Error', 'Error: Import PCAP File before Analysing!')    
                return    

        elif atk_selection == "ARP Poisoning":                                                      #if attack selected is "ARP Poisoning"
            try:                                                                                            #validation #2 - check if a file is imported, if no error - continue
                pno, atk, src, smac, dst, dmac, dt, detection = process_pcap_arp(filename)          #process_pcap_arp function - pass in filename, store return variables
            except:                                                                                         #validation #2 - if error - display message box alerting user to import file
                messagebox.showerror('User Error', 'Error: Import PCAP File before Analysing!')    
                return
    except:                                                                                                 #validation #1 - if error - display message box alerting user to select an attack
        messagebox.showerror('User Error', 'Error: Select Attack before Analysing!')    
        return

#-------------------------------------------------------#
#configure labels on analysis to display data returned from process_pcap_? function

    if atk_selection == "SYN Attack":
        
        smac_label.grid_forget()                                                    #remove labels from possible prior analysis
        dmac_label.grid_forget()

        src_ip_label.configure(text='Source IP: {}'.format(src))                    #alter text
        src_ip_label.grid(column=0, row=0, padx=50, pady=80,ipadx=25, ipady=15)     #display widget

        dest_ip_label.configure(text='Destination IP: {}'.format(dest))                   #
        dest_ip_label.grid(column=2, row=0, padx=50, ipadx=20, ipady=15)                 # #
                                                                                        # # #
        time_label.configure(text='Data / Time: {}'.format(dt))                           #
        time_label.grid(column=0, row=1, padx=50, ipadx=17, ipady=15)                     #
                                                                                          #
        protocol_label.configure(text='Protocol: {}'.format(prot))                        #
        protocol_label.grid(column=2, row=1, padx=50, ipadx=68, ipady=15)                 #
                                                                                          #
        detection_label.configure(text='{}'.format(detection))                            #
        detection_label.grid(column=1, row=3, ipadx=50, ipady=15)                         #
    
    elif atk_selection == "ARP Poisoning":

        protocol_label.grid_forget()                                                #remove labels from possible prior analysis

        src_ip_label.configure(text='{}'.format(src))                               #alter text
        src_ip_label.grid(column=0, row=0, padx=50, pady=80,ipadx=25, ipady=15)     #display widget

        dest_ip_label.configure(text='{}'.format(dst))                                    #
        dest_ip_label.grid(column=2, row=0, padx=50, ipadx=20, ipady=15)                 # #
                                                                                        # # #
        time_label.configure(text='Data / Time: {}'.format(dt))                           #
        time_label.grid(column=0, row=3, padx=50, ipadx=17, ipady=15)                     #
                                                                                          #
        smac_label.configure(text='{}'.format(smac))                                      #
        smac_label.grid(column=0, row=1, padx=50, ipadx=17, ipady=15)                     #
                                                                                          #
        dmac_label.configure(text='{}'.format(dmac))                                      #
        dmac_label.grid(column=2, row=1, padx=50, ipadx=68, ipady=15)                     #
                                                                                          #
        detection_label.configure(text='{}'.format(detection))                            #
        detection_label.grid(column=1, row=3, ipadx=30, ipady=15)                         #

#-------------------------------------------------------#
#check attack status - configure detection label

    if atk == True:                                                                         #if attack is true
        detection_label.configure(bg_color = "red")                                             #configure label to red, display packet number (as well as detection message)
        detection_label.configure(text='{}\nPacket Number: {}'.format(detection,pno))
        
    else:                                                                                   #if attack is not true
        detection_label.configure(bg_color = "green")                                           #configure label to green, retain original detection message (packet number not required)

#--------------------------------------------------------#
#map markers

    truesrc, sep, tail = src.partition(":")                         #separate return ip, store ip only (not port)
    lat,long = get_location(truesrc)                                #get_location function - pass in ip, store latitude + longitude
    #print("Latitude Data: ",lat,"\nLongitude Data: ",long)          #testing purposes - test case 13-14

    for marker in markers:                                          #delete list of prior markers (from any previous analysis runs)
            marker.delete()

    try:                                                            #if ip contains geolocation data (returns data, doesn't error)
        markers.append(map.set_marker(lat, long, text=truesrc))         #add marker to map + add text displaying ip
        print("IP Avaiable for Visualisation")                          #output to terminal that ip is available on the map
        warning_label.grid(column=2,row=3)                              #display warning label - ip may be spoofed, marker may not be accurate to attacker location
    except:                                                         #if ip doesn't contain geolocation data (returns none, errors)
        print("IP Unavailable for Visualisation")                       #output to terminal that ip is not available on the map
        warning_label.grid_forget()                                     #remove warning label

#-------------------------------------------------------#
#changeframe to analysis page automatically

    time.sleep(1)
    changeframetest("analysis")

#########################################################################################################################################
#root Tk

root = customtkinter.CTk()                  #root Tk frame
root.attributes('-fullscreen',False)        #fullscreen = false
root.geometry("1100x580")                   #window size
root.title('Network Traffic Analyser')      #Title
root.configure(bg='#000000')                #background colour        

root.rowconfigure(0, weight=1)              #row + column config = 1x1
root.columnconfigure(0, weight=1)

#########################################################################################################################################
#main frame

main = customtkinter.CTkFrame(root, bg_color='#4f4c4c')     #main frame
main.grid(row=0,column=0,sticky='news')                     #grid main frame onto root

main.grid_rowconfigure(0,weight=1)                          #row + column config = 2x1
main.grid_columnconfigure(1, weight=1)


#########################################################################################################################################
#navigation from - left side of main frame

navigation_frame = customtkinter.CTkFrame(main, corner_radius=0) #navigation frame
navigation_frame.grid(column=0, row=0, sticky="nesw")            #grid navigation onto main
navigation_frame.grid_rowconfigure(6, weight=1)                  #row + column config = 1x7

#-------------------------------------------------------#
#navigation frame widgets

navigation_frame_label = customtkinter.CTkLabel(navigation_frame, text="  Attack Analysis",
                                            image=attack_symbol, compound="left", font=customtkinter.CTkFont(size=15, weight="bold"))       #title
navigation_frame_label.grid(row=0, column=0,padx=(0,20), pady=20, ipadx=20)

home_button = customtkinter.CTkButton(navigation_frame, corner_radius=0, height=40, border_spacing=10, text="  Home",
                                            fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),      #home button
                                            image=home_symbol, anchor="w",command=lambda:changeframetest("home"))
home_button.grid(row=1, column=0, sticky="ew")

prep_frame_button = customtkinter.CTkButton(navigation_frame, corner_radius=0, height=40, border_spacing=10, text="  Preparation",
                                            fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),      #preparation button
                                            image=prep_symbol, anchor="w",command=lambda:changeframetest("prep"))
prep_frame_button.grid(row=2, column=0, sticky="ew")

analysis_frame_button = customtkinter.CTkButton(navigation_frame, corner_radius=0, height=40, border_spacing=10, text="  Analysis",
                                            fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),      #analysis button
                                            image=analysis_symbol, anchor="w",command=lambda:changeframetest("analysis"))
analysis_frame_button.grid(row=3, column=0, sticky="ew")

map_frame_button = customtkinter.CTkButton(navigation_frame, corner_radius=0, height=40, border_spacing=10, text="  Map",
                                            fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),      #map button
                                            image=map_symbol, anchor="w",command=lambda:changeframetest("map"))
map_frame_button.grid(row=4, column=0, sticky="ew")

exit_button = customtkinter.CTkButton(navigation_frame, text="Exit", command=root.destroy)                                                  #exit button
exit_button.grid(row=6, column=0, padx=20, pady=20, sticky="s")


#########################################################################################################################################
#home frame - 1/4 right side of main frame

home_frame = customtkinter.CTkFrame(main, corner_radius=0, fg_color="transparent")  #home frame
home_frame.grid_columnconfigure(0,weight=1)                                         #row + column config = 1x4
home_frame.grid_rowconfigure(3,weight=1)

#-------------------------------------------------------#
#home frame widgets

home_title_label = customtkinter.CTkLabel(home_frame, text= "Network Traffic Analysis Tool", compound="left", font=customtkinter.CTkFont(size=20, weight="bold"))               #title
home_title_label.grid(column=0, row=0, pady=35)

home_instructions = customtkinter.CTkTextbox(home_frame, height=230, width=500, text_color='white', activate_scrollbars=False)
home_instructions.insert("0.0", "             Import and analyse network traffic, and discover attacks within packets\n\n                              \
Visualise important data and track potential attackers\n\n\nOn the 'Preparation' Tab:\n\n\
        - Import a PCAP file\n\n        - Select an attack you wish to discover\n\n       - Move to the 'Analysis' Tab for results\n\n        - Visuale IP's on the 'Map' Tab") #instructions
home_instructions.configure(state='disabled')
home_instructions.grid(column=0, row=1)

                                                                                                                                                                                
home_image_label = customtkinter.CTkLabel(home_frame, text="", image=network_home_image, compound="center")                                                                     #image
home_image_label.grid(column=0, row=3)

#########################################################################################################################################
#prep frame - 2/4 right side of main frame

prep_frame = customtkinter.CTkFrame(main, corner_radius=0, fg_color="transparent") #prep frame
prep_frame.grid_columnconfigure(0,weight=1)                                        #row + column config = 1x5
prep_frame.grid_rowconfigure(4,weight=1)

#-------------------------------------------------------#
#preparation frame widgets

prep_title_label = customtkinter.CTkLabel(prep_frame, text= "Preparation", compound="left", font=customtkinter.CTkFont(size=20, weight="bold"), bg_color="#222222")     #title
prep_title_label.grid(column=0, row=0, pady=35, ipadx=240, ipady=18)

import_button = customtkinter.CTkButton(prep_frame, text="Import PCAP", command=importfolder)                                                                           #import button
import_button.grid(column=0, row=1, pady=20)

import_success_label = customtkinter.CTkLabel(prep_frame, text='', font=customtkinter.CTkFont(size=12, weight="normal"))                                                #import success label

attack_selection = customtkinter.CTkOptionMenu(master=prep_frame, values=["SYN Attack", "ARP Poisoning"], command = attackselection)                                    #attack selection optionmenu
attack_selection.grid(column=0, row=3, pady=40)
attack_selection.set("Select Attack")

analyse_button = customtkinter.CTkButton(prep_frame, text="Analyse",command=analysis)                                                                                   #analyse button
analyse_button.grid(column=0, row=4, pady=20)

#########################################################################################################################################
#analysis frame - 3/4 right side of main frame

analysis_frame = customtkinter.CTkFrame(main, corner_radius=0, fg_color="transparent")      #analysis frame
analysis_frame.grid_columnconfigure(2,weight=1)                                             #row + column config = 3x4
analysis_frame.grid_rowconfigure(3,weight=1)

#-------------------------------------------------------#
#analysis frame widgets

src_ip_label = customtkinter.CTkLabel(analysis_frame, text= "src_ip + port", compound="none", anchor='center', 
                                      font=customtkinter.CTkFont(size=12, weight="normal"), bg_color="#202020")                 #src_ip - universal

dest_ip_label = customtkinter.CTkLabel(analysis_frame, text= "dest_ip + port", compound="none", anchor='center', 
                                       font=customtkinter.CTkFont(size=12, weight="normal"), bg_color="#202020")                #dest_ip - universal

time_label = customtkinter.CTkLabel(analysis_frame, text= "time", compound="none", anchor='center', 
                                    font=customtkinter.CTkFont(size=12, weight="normal"), bg_color="#202020")                   #time - universal

protocol_label = customtkinter.CTkLabel(analysis_frame, text= "protocol", compound="none", anchor='center', 
                                        font=customtkinter.CTkFont(size=12, weight="normal"), bg_color="#202020")               #protocol - syn attack

detection_label = customtkinter.CTkLabel(analysis_frame, text= "<attack> <not> detected", compound="none", anchor='center',     #detection - universal
                                         font=customtkinter.CTkFont(size=12, weight="normal"), bg_color="#202020")

warning_label = customtkinter.CTkLabel(analysis_frame, text= "*Warning - IP may be spoofed, Visualisation may be inaccurate",   #map warning label
                                       compound="none", anchor='center', font=customtkinter.CTkFont(size=10, weight="normal"), 
                                       bg_color="transparent")

smac_label = customtkinter.CTkLabel(analysis_frame, text= "smac", compound="none", anchor='center',                             #src_mac - arp poisoning
                                        font=customtkinter.CTkFont(size=12, weight="normal"), bg_color="#202020")
                                        
dmac_label = customtkinter.CTkLabel(analysis_frame, text= "dmac", compound="none", anchor='center',                             #dst_mac - arp poisoning
                                        font=customtkinter.CTkFont(size=12, weight="normal"), bg_color="#202020")

#########################################################################################################################################
#map frame - 4/4 right side of main frame

map_frame = customtkinter.CTkFrame(main, corner_radius=0, fg_color="transparent")   #map frame
map_frame.grid_columnconfigure(0,weight=1)                                          #row + column config = 1x1
map_frame.grid_rowconfigure(0,weight=1)

#-------------------------------------------------------#
#map frame widgets

markers = []    #array of map markers

map = tkintermapview.TkinterMapView(map_frame, width=880, height=700, corner_radius=0)                  #map
map.set_tile_server("https://mt0.google.com/vt/lyrs=m&hl=en&x={x}&y={y}&z={z}&s=Ga", max_zoom=22)       #map type = googlemaps
map.set_address("Europe")                                                                               #intial address = Europe
map.set_zoom(1)                                                                                         #zoom = 1, view world map
map.grid(column=0, row=0)                                                                               #grid map onto map_frame

#########################################################################################################################################
#entrypoint / start

changeframe(main)       #initialise / changeframe to main
root.mainloop()         #gui continuation

