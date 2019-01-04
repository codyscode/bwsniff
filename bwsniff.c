/* Cody Cunningham */

#include<stdlib.h> 
#include<string.h>
#include<stdbool.h>
#include<pcap.h>
#include<net/ethernet.h>
#include <unistd.h>
#include <ncurses.h>
#include <pthread.h>
#include "bwsniff.h"

Entry *head, *tail;
char *dev_name;

int main(int argc, char **argv)
{
	pcap_if_t *dev = NULL;
	pcap_if_t *dev_list = NULL;
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Check if user has root permissions */
	if (geteuid() != 0)
	{
		fprintf(stderr, "Error: bwsniff must be run as root.\n");
		exit(1);
	}
	
	/* Find available devices */
	pcap_findalldevs(&dev_list, errbuf);
	if (dev_list == NULL)
	{
		fprintf(stderr, "Error finding devices: %s\n", errbuf);
		exit(1);
	}

	/* Initialize ncurses and print the setup screen */
	initscr();
	printw("Device:         Description:\n");
	printw("--------------  ----------------------------\n");
	int count = 0;
	for(dev = dev_list; dev != NULL; dev = dev->next)
	{
		if (dev->description == NULL)
		{
			dev->description = "(No description)";
		}
		printw("%d. %-12s %s\n", ++count, dev->name, dev->description);
	}
	printw("\nSelect a device to sniff: ");

	/* Loop until user selects supported device*/
	while (handle == NULL)
	{
		int choice = getch() - '0';
		if (choice < 1 || choice > count)
		{
			printw("\nInvalid selection, try again: ");
			continue;
		}
		for(dev = dev_list; choice > 1  && dev != NULL; choice--, dev = dev->next) {}
		/* Open device, only capture sizeof ethhdr from each packet to save overhead */
		handle = pcap_open_live(dev->name, sizeof(struct ethhdr), 1, 0, errbuf);
		if (handle == NULL)
		{
			printw("\nUnable to open device: %s, try again: ", errbuf);
			continue;
		}
		if (pcap_datalink(handle) != DLT_EN10MB)
		{
			printw("\nDevice doesn't support the required Ethernet headers, try again: ");
			pcap_close(handle);
			handle = NULL;
		}
	}
	dev_name = dev->name;

	/* Reconfigure ncurses and start the main screen */
	nodelay(stdscr, true);
	noecho();
	curs_set(0);
	pthread_t thread;
	pthread_create(&thread, NULL, main_screen, NULL);
	/* Start the packet capture loop */
	pcap_loop(handle , -1 , process_packet , NULL);
}

/* Takes data from captured packet and passes it to update_byte_counts() */
void process_packet(unsigned char *args, const struct pcap_pkthdr *pkt_hdr, const unsigned char *buffer)
{
	struct ethhdr *eth_hdr= (struct ethhdr *)buffer;
	update_byte_count(eth_hdr->h_source, pkt_hdr->len, true);
	update_byte_count(eth_hdr->h_dest, pkt_hdr->len, false);
}

/* Updates appropriate byte counts for given MAC depending on whether is sender or receiver */
void update_byte_count(unsigned char* mac, int bytes, bool is_sender)
{	
	/* Search for entry matching MAC */
	Entry *cursor = head;
	while(cursor != NULL && strncmp(cursor->mac, mac, ETH_ALEN) != 0)
	{
		cursor = cursor->next;			
	}
	/* If MAC isn't found add a new entry */
	if (cursor == NULL)
	{
		cursor = calloc(1, sizeof(Entry));
		memcpy(cursor->mac, mac, ETH_ALEN);
		sprintf(cursor->desc, "%.17s", find_description(mac));
		if (head == NULL)
		{
			head = tail = cursor;
		}
		else
		{
			tail->next = cursor;
			tail = cursor;
		}
	}
	/* Update appropriate byte counts */
	if (is_sender) 
	{
		cursor->sent += bytes;
		cursor->sent_wndw += bytes;
	}
	else 
	{
		cursor->recv += bytes;
		cursor->recv_wndw += bytes;
	}
}

/* Returns vendor name or protocol description for a given mac */
char *find_description(unsigned char *mac)
{
	char oui[7];
	sprintf(oui, "%.2X%.2X%.2X", mac[0], mac[1], mac[2]);
	/* Return protocol description if oui is reserved, all protocol descriptions
	   must begin with '[' which is used to differentiate from vendors. */
	if (strcmp("01005E", oui) == 0)
	{
		return "[Multicast IPv4]";
	}
	else if (strcmp("333300", oui) <= 0 && strcmp("3333FF", oui) >= 0)
	{
		return "[Multicast IPv6]";
	}
	else if (strcmp("CF0000", oui) <= 0 && strcmp("CFFFFF", oui) >= 0)
	{
		return "[PPP]";
	}
	else if (strcmp("FFFFFF", oui) == 0)
	{
		return "[Broadcast]";
	}
	/* Otherwise return vendor info for that oui */
	else
	{
		int vendors_len = sizeof(vendors) / sizeof(VendorInfo);
		int low = 0;
		int high = vendors_len - 1;
		int mid;
		while (low <= high)
		{
			mid = (low + high) / 2;
			int equality = strcmp(vendors[mid].oui, oui);
			if(equality < 0)
			{
				low = mid + 1;
			}
			else if (equality > 0)
			{
				high = mid - 1;
			}
			else
			{
				return vendors[mid].vendor;
			}
		}
		return "Unknown Vendor";	
	}
}

/* Formats data, prints the main screen, and handles user input once per TIME_WINDOW */
void *main_screen()
{
	static bool is_filtered = true;
	while(true)
	{
		clear();	
		printw("Device: %s\n", dev_name);
		printw("View: %s (Press 1 to toggle)\n", is_filtered ? "Filtered" : "All MACs");
		printw("                                      Rate (Mbps)       Total (MiB)\n");
		printw("MAC Address        Vendor             Up       Down     Sent      Received\n");
		printw("-----------------  -----------------  -------- -------- --------- ---------\n");
		
		Entry *cursor;
		for (cursor = head; cursor != NULL; cursor = cursor->next)
		{
			/* If filtered mode, omit protocol addresses, which all have desc[0] == '[' */
			if (is_filtered && cursor->desc[0] == '[')
			{
				continue;
			}
			/* Convert raw byte counts to units */
			float sent_mib = cursor->sent / BYTES_IN_MEBIBYTE;
			float recv_mib = cursor->recv / BYTES_IN_MEBIBYTE;
			float sent_mbps = cursor->sent_wndw / BYTES_IN_MEGABIT / TIME_WINDOW;
		 	float recv_mbps = cursor->recv_wndw / BYTES_IN_MEGABIT / TIME_WINDOW;
		 	/* Reset sent and received window counts every TIME_WINDOW */
		 	cursor->sent_wndw = 0;
			cursor->recv_wndw = 0;
			/* Format and print output */
			char mac_str[18];
			sprintf(mac_str, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", 
				cursor->mac[0], cursor->mac[1], cursor->mac[2], cursor->mac[3], cursor->mac[4], cursor->mac[5]);
			printw("%-18s %-18s %8.3f %8.3f %9.3f %9.3f\n", mac_str, cursor->desc, sent_mbps, recv_mbps, sent_mib, recv_mib);
		}
		refresh();
		sleep(TIME_WINDOW);
		/* Read user input to toggle filtered mode */
		if (getch() == '1')
		{
			is_filtered = is_filtered ? false : true;
		}
	}
	return NULL;
}