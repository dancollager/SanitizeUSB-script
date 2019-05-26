#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <memory.h>

/*
* Script to sanitize USB / Partition.
* computer forensics
* Engineer Siler Amador
* Leidy Sarria
* Daniel Collazos
* 2019-Unicauca
*/

// CONSTANTS
const char DEVICES_LIST[] = "fdisk -l | egrep -o '(/dev/[^:]*):|[^:]*B,' | awk -F: '{print $1}'> /tmp/sterilizeUSB";
const char DEVICE_SELECTED[] = "fdisk -l /";
const char CHECK[] = " | xxd | grep -v '0000 0000 0000 0000 0000 0000 0000 0000' | wc -l >> /tmp/checkUSB";
const char CHECK1[] = " | xxd | wc -l >> /tmp/checkUSB";
const char ZERO[] = "sudo dd if=/dev/zero of=/";
const char URANDOM[] = "sudo dd if=/dev/urandom of=/";
const char base_string[] = "";

// VARIABLES
int deviceID=-1, partitionID = 0, result, mode, c, cycles = 3, count =0 ;
char buff[255], commandZERO[255], commandURANDOM[255],
device[255][255], size[255][255], name[50], ch;
FILE *file;

// FUNCTIONS
void manual(int);
void automatic();
void format();
void umount();
void clear();

int main() {

	clear();

	printf("\n*******************************************\n");
	printf("***\t\t\t\t\t***\n");
	printf("*** Script for sterilize USB/Partition  ***");
	printf("\n***\t\t\t\t\t***");
	printf("\n*******************************************\n");

	if (getuid()){
		printf("\n\t* You need privileges of user! * \n");
		return 0;
	} 

	result = system(DEVICES_LIST); // List devices and save in tmp
	file = fopen("/tmp/sterilizeUSB","r"); // Query devices in tmp directory
	c = getc(file);
	printf("\nDETECTED DEVICES:\t\n\n");

    while(c != EOF){

      fgets(device[count],255,(FILE*)file); // read a line(name) and save in device variable
      device[count][strlen(device[count]) - 1] = '\0'; // Delete line break
      fgets(size[count],255,(FILE*)file);  // read a line(size) and save in size variable
      size[count][strlen(size[count]) - 1] = '\0'; // Delete line break
      printf("* Device #%d: /%s of size: %s\n",(count+1),device[count],size[count]);
      count ++;
      c = getc(file); // move to another line
    }

    fclose(file); // close file
    printf("\nEnter the number of device (%i detected) :", count);

    scanf("%d", &deviceID);
    while(deviceID < 0 || deviceID > count){  
    	while ((ch = getchar()) != '\n')
            putchar(ch);
    	printf("\nInvalid number, enter again (0 to exit):"); 	
    	scanf("%d", &deviceID);
    }

    if(deviceID == 0 ) return 0;

    printf("\n*******************************************\n");
    printf("\tSelected Device#%d /%s",deviceID,device[deviceID-1]);
    printf("\n*******************************************\n");
    
    char link[255]; // for to join variables char
    strcpy(link, "fdisk -l /");
    strcat(link, device[deviceID-1]);
    result = system(link);  // show partitions of a device

    strcat(link, " |  egrep -o '(");
    strcat(link,device[deviceID-1]);
    strcat(link, "[^:])'  > /tmp/sterilizePartition");
    result = system(link);   // save partitions in tmp directory

    file = fopen("/tmp/sterilizePartition","r");
    count = 0;
    c = getc(file);
    while(c != EOF){
      count ++; // count number of partitions of a device
      fgets(buff,255,(FILE*)file);
      c = getc(file);
    }
    fclose(file);

    if (count != 0) {
    	printf("\n*********************************************\n");
    	printf(" \t Enter the partition of /%s",device[deviceID-1]);
    	printf("\n*********************************************\n");
    	printf("\nNOTE: for to sanitize the device complete enter '99'\n");

    	if(strncmp(device[deviceID-1],"dev/mmcblk0",9)==0) printf("Partition /%sp",device[deviceID-1] );
    	else printf("Partition /%s",device[deviceID-1] );
    	
    	scanf("%d",&partitionID);
    	while((partitionID < 0 || partitionID > count && partitionID != 99)){  
    		while ((ch = getchar()) != '\n') putchar(ch);
    		printf("\nInvalid number, enter again (0 to exit):"); 	
    		scanf("%d", &partitionID);
    	}
    	if(partitionID == 0 ) return 0;
    	printf("\n*********************************************\n");
    	if(strncmp(device[deviceID-1],"dev/mmcblk0",9)==0) printf("\t Sterilize /%sp%d\n",device[deviceID-1],partitionID);
    	else if(count != 0 & partitionID !=99) printf("\t Sterilize /%s%d",device[deviceID-1],partitionID);
		printf("\n*********************************************\n");
	}

	printf("\n************** Operating modes **************\n");	
	printf("1. Manual sterilization (define cycles)\n");
	printf("2. Automatic sterilization\n");	
	printf("3. Cancel\n");	
	printf("Enter your selection: ");
	scanf("%d",&mode);	

    while((mode < 0 || mode > 4 )){  
    	while ((ch = getchar()) != '\n') putchar(ch);
    	printf("\nInvalid number, enter again (0 to exit):"); 	
    	scanf("%d", &mode);
    }
    if(mode == 0 ) return 0;

    // Prepare commands for execute in shell Linux
	char id [255];
    sprintf(id, "%s%d", base_string, partitionID);
	strcpy(commandZERO,ZERO);
	strcat(commandZERO,device[deviceID-1]);
	if(count != 0 & partitionID !=0) {
		if(strncmp(device[deviceID-1],"dev/mmcblk0",9)==0) strcat(commandZERO, "p");
		strcat(commandZERO, id);	
	} 	
	strcat(commandZERO," bs=1024");
	strcpy(commandURANDOM,URANDOM);
	strcat(commandURANDOM,device[deviceID-1]);
	if(count != 0 & partitionID !=0) {
		if(strncmp(device[deviceID-1],"dev/mmcblk0",9)==0) strcat(commandURANDOM, "p");
		strcat(commandURANDOM, id);	
	} 
	strcat(commandURANDOM," bs=1024");

	// Select action
	switch(mode){
		case(1):
			printf("Select the number of cycles[3,100]: ");
			scanf("%d",&cycles);
			while((cycles < 3 || cycles > 101 ) && cycles != 0){  
    			while ((ch = getchar()) != '\n') putchar(ch);
    			printf("\nInvalid number, enter again (0 to exit):"); 	
    			scanf("%d", &cycles);
    		}
    		if(cycles == 0 ) return 0;
    		manual(cycles);
			break;
		case(2):
			automatic();
			break;
		case(3):
			printf("\nGood bye.\n");
			return 0;
		default:
			break;
		}
	printf("\n************* Sterilized! *****************\n");
	return 0;	
}

// Functions 
void manual(int cycles) {
	printf("\n******* sterilization process *******\n");
	for(int i=0;i<cycles;i++){
		result = system(commandZERO); 
		result = system(commandURANDOM); 
		}
		result = system(commandZERO);
		umount(); 
	}
	
void automatic(){
	manual(3);
	// Check 
	printf("\n*********************************************\n");
	printf("\n***** \t\t\t\t\t ****\n");
	printf("\n*****\t Check Sterilized USB/Partition  ****\n");
	printf("\n***** \t\t\t\t\t ****\n");
	printf("\n*********************************************\n");
	printf("\nEnter 1(yes) or 0(not) for check sterilization\n(this proccess can take SEVERAL minutes):");
	scanf("%d",&c);
	while(c < 0 || c > 1){  
    			while ((ch = getchar()) != '\n') putchar(ch);
    			printf("\nInvalid number, enter again (0 to exit):"); 	
    			scanf("%d", &c);
    		}
	if(c==0) return;
    char general[255];
    strcpy(general, "dd if=/");
    strcat(general, device[deviceID-1]);
	char id [255];
    sprintf(id, "%s%d", base_string, partitionID);
    if(count != 0 & partitionID !=0){
    	if(strncmp(device[deviceID-1],"dev/mmcblk0",9)==0) strcat(general, "p");
    	strcat(general, id);	
    } 
    strcat(general, CHECK);
    result = system(general);  
    char general1[255];
    strcpy(general1, "dd if=/");
    strcat(general1, device[deviceID-1]);
    if(count != 0 & partitionID !=0) {
    	if(strncmp(device[deviceID-1],"dev/mmcblk0",9)==0) strcat(general1, "p");
    	strcat(general1, id);	
    }   
    strcat(general1, CHECK1);
    result = system(general1); 
    file = fopen("/tmp/checkUSB","r"); 
    char bad[255],total[255];
    fgets(bad,255,(FILE*)file);
    bad[strlen(bad) - 1] = '\0';
    fgets(total,255,(FILE*)file);
    total[strlen(total) - 1] = '\0';    
    printf("\n Number of octects no empty: %s/%s \n",bad, total);
    int no_empty = (intptr_t) bad;
    int size_device = (intptr_t) total;
    float rate = 100 - (no_empty / size_device); 
    printf("\n Sterilization percentage: %f %% \n", rate);
    fclose(file);
    printf("%s\n", general);
    printf("%s\n", general1);
	}

void format(){
	printf("\n***************** FORMAT FAT 32 *****************\n");
	printf("\nEnter a name for USB/Partition: ");
	scanf("%s", &name[0]);
	char join[255];
	strcpy(join, " mkfs.vfat -F 32 -n ");
	strcat(join, name);
	strcat(join," /");
	strcat(join, device[deviceID-1]);
    char ccount = (char)partitionID;
    if(count != 0 & partitionID !=0) strcat(join, ccount+" ");	
    result = system(join);  
}

void umount() {
	char general[255];
	strcpy(general, "umount /");
	strcat(general, device[deviceID-1]);
    char ccount = (char)partitionID;
    if(count != 0 & partitionID !=0) strcat(general, ccount+" ");	
    result = system(general);  
    format();
}

void clear() {
	result = system("test -f /tmp/sterilizeUSB && rm /tmp/sterilizeUSB"); 
	result = system("test -f /tmp/sterilizePartition && rm /tmp/sterilizePartition"); 
	result = system("test -f /tmp/checkUSB && rm /tmp/checkUSB"); 
}