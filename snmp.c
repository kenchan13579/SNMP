#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
  /*GLOBAL*/
    netsnmp_session session, *ss;
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len;
    netsnmp_variable_list *vars;
    int status;
  /**********************/

// initialize connection to snmp agent
void init() {
    init_snmp("cs158b");
    /*
     * Initialize a "session" that defines who we're going to talk to
     */
    snmp_sess_init( &session );                   /* set up defaults */
    session.peername = strdup("localhost");
    session.version = SNMP_VERSION_1;
    session.community = "secret";
    session.community_len = strlen(session.community);

}
void snmpget(char* oid) {
   SOCK_STARTUP;
    ss = snmp_open(&session);                     /* establish the session */
    if (!ss) {
      snmp_sess_perror("ack", &session);
      SOCK_CLEANUP;
      exit(1);
    }
    printf("%s\n" , oid);
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    anOID_len = MAX_OID_LEN;
   get_node(oid, anOID, &anOID_len);
    snmp_add_null_var(pdu, anOID, anOID_len);// all OID should be paired with null for out going req
    status = snmp_synch_response(ss, pdu, &response); // sent req
}
void snmpgetnext(char* oid) {
   SOCK_STARTUP;
    ss = snmp_open(&session);                     /* establish the session */
    if (!ss) {
      snmp_sess_perror("ack", &session);
      SOCK_CLEANUP;
      exit(1);
    }
    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    anOID_len = MAX_OID_LEN;
   get_node(oid, anOID, &anOID_len);
    snmp_add_null_var(pdu, anOID, anOID_len);// all OID should be paired with null for out going req
    status = snmp_synch_response(ss, pdu, &response); // sent req
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
 int ifNumber = getNumOfIfs();
 printf("%i\n", ifNumber);
  int done = 0;
 char *prev ="ipAdEntAddr" ;
 printf("<---Interfaces--->\nInterface -> IP Address\n");
 while ( !done ) {
  snmpgetnext(prev);
    if ( vars = response->variables)
    {
      if ( vars->type == ASN_INTEGER) {
        done = 1;
        break;// end of the row
      }

      u_char *sp= vars->val.bitstring;
      char ip[20];
      sprintf(ip , "%i.%i.%i.%i",sp[0],sp[1],sp[2],sp[3]);
      prev = ip ;
      //sp[vars->val_len] = '\0';
     // prev = sp;
      cleanup();
      snmpgetnext("ipAdEntIfIndex");
      vars = response->variables;
      long* n = vars->val.integer;

      printf(" %i -> %s" , (int) *n, ip);
      free(sp);
    }
 }
}
void showNeighbor() {
 /* get_node("ifNumber.0",anOID , &anOID_len);
  snmp_add_null_var(pdu , anOID , anOID_len);
  status = snmp_synch_response(ss,pdu,&response);;
  if ( status == STAT_SUCCESS && response->errstat)*/
}
void showTraffic() {

}
int main(int argc, char ** argv)
{
    int count=1;
    init();
    showInteferfaces();

    /*
     * Clean up:
     *  1) free the response.
     *  2) close the session.
     */

    return (0);
} /* main() */
