#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#define true 1
#define false 0
  /*GLOBAL*/
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
void init() {
    init_snmp("cs158b");
    /*
     * Initialize a "session" that defines who we're going to talk to
     */
    snmp_sess_init( &session );                   /* set up defaults */
    session.peername = strdup("localhost");
    session.version = SNMP_VERSION_2c;
    session.community = "public";
    session.community_len = strlen(session.community);

}
void snmpcommand(char* oid,int cmd) {
  SOCK_STARTUP;
 
    ss = snmp_open(&session);                     /* establish the session */
    if (!ss) {
      snmp_sess_perror("ack", &session);
      SOCK_CLEANUP;
      exit(1);
    }
    pdu = snmp_pdu_create(cmd);
     if ( cmd == SNMP_MSG_GETBULK) {
    pdu->non_repeaters  = 0;
    pdu->max_repetitions  = 10; 
 }
 printf("%s\n",oid);
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
void cleanup()  {
   if (response)
      snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;

}
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
int getNumOfIfs() {
  snmpget("ifNumber.0");
 if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
    if (  vars = response->variables) {
      if ( vars->type == ASN_INTEGER) {
        long* n = vars->val.integer;
        cleanup();
        return (int) *n;
      }
    }
  } else {
    errHandles(status);

  }
  cleanup();
  return -1;
}
void showInteferfaces() {
 struct interfaces ifs[10];
 char *oid ="ipAdEntAddr" ;
 int counter = 0 ;
 snmpbulkget(oid);
 printf("----Interfaces----\nNumber --> IP \n");
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
    // 1st forloop to get the ip address ::ipAdEntAddr
    for ( vars = response->variables;vars; vars = vars->next_variable) {
      if ( vars->type == ASN_IPADDRESS) {
        char *temp = (char*) malloc(50);
        snprint_ipaddress(temp , 50 , vars,NULL ,NULL,NULL);
        // Only IP is needed so get rid of the unrelated string
        int len = strlen("IpAddress: ");
        int newLen = strlen(temp)-len;
        strncpy(temp , temp+len, newLen);
        *(temp+newLen) = '\0';
        strcpy(ifs[counter++].ipaddress , temp); // add to if struct
        free(temp);
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
  printf("\n\n");
}
void showNeighbor() {
  int done = false;
  char *ifIndex_oid = "ipNetToMediaPhysAddress ";
  char *ip_oid = "ipNetToMediaNetAddress";
  snmpbulkget(ifIndex_oid);
  for ( vars = response->variables;vars; vars = vars->next_variable) {
    
    print_variable(vars->name, vars->name_length, vars);
    done = !done;
  }
  cleanup();
}
void showTraffic() {
  
}
int main(int argc, char ** argv)
{
    int count=1;
    init();
    showInteferfaces();
    showNeighbor();
    /*
     * Clean up:
     *  1) free the response.
     *  2) close the session.
     */

    return (0);
} /* main() */
