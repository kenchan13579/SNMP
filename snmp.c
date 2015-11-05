#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#define true 1
#define false 0
#define lastInOctets 0
#define lastOutOctets 1
  /*GLOBAL VALUES that will be used for SNMP request and response*/
    netsnmp_session session, *ss;
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len;
    netsnmp_variable_list *vars;
    int status;
    struct interfaces {
      char ipaddress[20];
      int ifIndex;
    };
  /**********************/

// initialize connection to snmp agent
void init(char* ip , char* community) {
    init_snmp("cs158b");
    /*
     * Initialize a "session" that defines who we're going to talk to
     */
    snmp_sess_init( &session );                   /* set up defaults */
    session.peername = strdup(ip); // ip
    session.version = SNMP_VERSION_2c;
    session.community = community; // community
    session.community_len = strlen(session.community);

}
// a higher abstraction function takes oid string and SNMP methods and call
void snmpcommand(char* oid,int cmd) {
    SOCK_STARTUP;
    ss = snmp_open(&session);                     /* establish the session */
    if (!ss) {
      snmp_sess_perror("ack", &session);
      SOCK_CLEANUP;
      exit(1);
    }
    pdu = snmp_pdu_create(cmd);
     if ( cmd == SNMP_MSG_GETBULK) { // for bulkget only
    pdu->non_repeaters  = 0;
    pdu->max_repetitions  = 50;
 }
    anOID_len = MAX_OID_LEN;
   get_node(oid, anOID, &anOID_len);
    snmp_add_null_var(pdu, anOID, anOID_len);// all OID should be paired with null for out going req
    status = snmp_synch_response(ss, pdu, &response); // sent req
}

void snmpget(char* oid) {
   snmpcommand(oid,SNMP_MSG_GET);
}
void snmpgetnext(char* oid) {
  snmpcommand(oid,SNMP_MSG_GETNEXT);
}
void snmpbulkget(char *oid) {
  snmpcommand(oid, SNMP_MSG_GETBULK );
}
// Need to clean after each SNMP call, otherwise program fails
void cleanup()  {
   if (response)
      snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;

}
// handle err if connection fails
void errHandles(int stat) {
 if (status == STAT_SUCCESS)
        fprintf(stderr, "Error in packet\nReason: %s\n",
                snmp_errstring(response->errstat));
      else if (status == STAT_TIMEOUT)
        fprintf(stderr, "Timeout: No response from %s.\n",
                session.peername);
      else
        snmp_sess_perror("snmpdemoapp", ss);

}
// helper function to parse OID ipaddress response value
char* parseIP(char* temp) {
  snprint_ipaddress(temp , 50 , vars ,NULL ,NULL,NULL);
  // Only IP is needed so get rid of the unrelated string
  int len = strlen("IpAddress: ");
  int newLen = strlen(temp)-len;
  strncpy(temp , temp+len, newLen);
  *(temp+newLen) = '\0';
  return temp;
}
struct interfaces monitor;// the interface to monitor
// Show agents current interface that has an ip
// MIB OID used: ipAdEntAddr
void showInteferfaces() {
  int monitor_index = 0; // this records the last interfaces that should be monitored
 struct interfaces ifs[10];
 char *oid ="ipAdEntAddr" ;
 int counter = 0 ;
 snmpbulkget(oid); // bulkget
 printf("-------------------------Interfaces-------------------------\n");
 printf("Number --> IP\n");
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
    // 1st forloop to get the ip address ::ipAdEntAddr
    for ( vars = response->variables;vars; vars = vars->next_variable) {
      if ( vars->type == ASN_IPADDRESS) {
        char tmp[50] ;
        strcpy(ifs[counter++].ipaddress , parseIP(tmp)); // add to if struct
        int cp = strcmp(tmp , "127.0.0.1");
        if (cp!=0) {
          monitor_index = counter;
          strcpy(monitor.ipaddress , tmp);
        }
        if (counter >= 10 ) {
          printf("Too many interfaces.\n");
          vars = vars->next_variable;
          break;
        }
      } else {
        counter = 0 ; // reset counter to 0
        break;
      }
   } // end 1st loop
   // 2nd forloop to get the if index IP-MIB::ipAdEntIfIndex
   for ( vars ;vars; vars = vars->next_variable) {
      if ( vars->type == ASN_INTEGER) {
        ifs[counter++].ifIndex = (int) *(vars->val.integer);
        if (counter == monitor_index) {
          monitor.ifIndex = (int) *(vars->val.integer);
        }
         if (counter >= 10 ) {
          printf("Too many interfaces.\n");
          break;
        }
      } else {
        break;
      }
   } // end 2nd loop
  } else {
    errHandles(status);
  }
 cleanup();
 // display the table
  counter--;
  while ( counter >= 0 ) {
    printf("%i  -->  %s\n" , ifs[counter].ifIndex, ifs[counter].ipaddress);
    counter--;
  }
  printf("------------------------------------------------------------\n");
  printf("\n\n");
}
// Show agent's nieghbor and Ips
// mib object used : ipNetToMediaIfIndex , ipNetToMediaNetAddress
void showNeighbor() {
  char ifIndex_oid[50] = "ipNetToMediaIfIndex";
  char ip_oid[50] = "ipNetToMediaNetAddress";
  printf("-----------------------Neighbor----------------------\n");
  printf("Interface  -->  Neighbor\n");
     while ( true ) {

    snmpgetnext(ifIndex_oid);
    int index ;
    char *ip ;
    vars  = response->variables;

    if ( vars->type == ASN_INTEGER) {
      char tmp[50] ;
     snprint_objid(tmp,50,vars->name,vars->name_length); // this returns response oid
      strcpy(ifIndex_oid,tmp); // update the oid for next getnext
      index = (int) *(vars->val.integer);
    } else {
      break;
    }
    cleanup();
    snmpgetnext(ip_oid);
    vars = response->variables;
    if ( vars->type == ASN_IPADDRESS) {
      char tmp[50];
      char oidTemp[50];
      snprint_objid(oidTemp,50,vars->name,vars->name_length);//this returns response oid
      strcpy(ip_oid,oidTemp); // update the oid for next getnext
      ip = parseIP(tmp);
    } else {
      break;
    }
    printf("%i  -->  %s\n" , index , ip);
    cleanup();
  }
  printf("----------------------------------------------------\n\n\n");
}
int max(int a , int b) {
  if ( a > b ) {
    return a;
  } else {
    return b;
  }
}
/**
 Calculate the current traffic and display the stat based on time interval provided
 MIB Object used : ifIntOctets, ifOutets
**/
void showTraffic(int timeInterval , int numberOfSamples) {
  char *monitorIp = monitor.ipaddress;
  int data[2];
  char ifInOctets[50] ;
  char ifOutOctets[50];
  //char ifSpeed[50];
  sprintf(ifInOctets , "%s.%i","ifInOctets",monitor.ifIndex);
  sprintf(ifOutOctets , "%s.%i","ifOutOctets",monitor.ifIndex);
  //sprintf(ifSpeed , "%s.%i","ifSpeed",monitor.ifIndex);
  printf("Monitoring %s ...\n", monitorIp);
  // initialize the first data "inoctets" and "outoctets"
  snmpget(ifInOctets);
  data[lastInOctets] = (int) *(response->variables->val.integer); // last in data
  cleanup();
  snmpget(ifOutOctets);
  data[lastOutOctets] = (int) *(response->variables->val.integer); // last out data
  cleanup();
  int totalTime = timeInterval;
  while ( numberOfSamples >= 0 ) {
      sleep(timeInterval);
      snmpget(ifInOctets);
      int inOctets = (int) *(response->variables->val.integer);
      cleanup();
      snmpget(ifOutOctets);
      int outOctets = (int) *(response->variables->val.integer);
      cleanup();
       // bytes per seconds ->  (bytes * 0.000001 per second) -> (Mb per second)
      long double traffic =  ( max( inOctets-data[lastInOctets] , outOctets-data[lastOutOctets])) * 0.001 / ( timeInterval ); // for kbps
      printf("At %i second  --> %Lf kbps. ( %.1LF mbps )\n" , totalTime , traffic, traffic*0.001);
      data[lastInOctets] = inOctets;
      data[lastOutOctets] = outOctets;
      totalTime += timeInterval;
      numberOfSamples--;
  }
}
/*
Input:
Time interval , number of sample, ip address, community
*/
int main(int argc, char ** argv)
{
  if ( argc != 5 ) {
    printf("Please provide Time interval between samples, Number of samples to take, IP address of the agent, and Community\n");
    return 0;
  }
  int timeInterval = atoi(argv[1]);
  int numberOfSamples = atoi(argv[2]);
  char* hostname = argv[3];
  char* community = argv[4];
  init( hostname, community); //ip , community
  showInteferfaces();
  showNeighbor();
  showTraffic(timeInterval , numberOfSamples);
    return 1;

} /* main() */
