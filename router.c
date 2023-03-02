#include "queue.h"
#include "skel.h"
// Structura folosita pentru a retine in coada pachetele
// ce trebuie trimise, dar pentru care nu se cunoaste
// adresa MAC destinatie.
struct unsent {
	uint32_t ip; // Adresa ip pe care trebuie trimise (next_hop)
	packet p; // Pachetul
};
/**
 * get_arp_entry - Functie care cauta liniar prin tabela de arp si in caz ca
 * gaseste adresa ip cautata intoarce intrarea din tabela.
 * @dest_ip - adresa ip cautata
 * @arp_table - tabela arp
 * @arp_table_len - dimensiunea tabelei
 * return - adresa intrarii din tabela pentru care se potriveste ip-ul cautat
 * (sau NULL daca nu se gaseste).
 */
struct arp_entry* get_arp_entry(struct in_addr dest_ip,
	struct arp_entry* arp_table, int arp_table_len)
{
	int index = -1;
	for (int i = 0; i < arp_table_len; i++) {
		if (dest_ip.s_addr == arp_table[i].ip)
			index = i;
	}
	// Daca nu gaseste nicio potrivire, intoarce NULL.
	return (index == -1 ? NULL : &arp_table[index]);
}
/**
 * prepare_icmp - Functie care pregateste icmp-ul pentru a fi trimis.
 * @iph - header-ul ip ddin pachet.
 * @type - tipul icmp-ului.
 */
void prepare_icmp(struct iphdr* iph, int type)
{
	// Construiesc un header icmp.
	struct icmphdr icmp;
	// Setez tipul icmp-ului.
	icmp.type = type;
	icmp.code = 0;
	// Calculez checksum-ul.
	icmp.checksum = 0;
	icmp.checksum = icmp_checksum((uint16_t *)&icmp, sizeof(struct icmphdr));
	// Retin primii 64 de octeti de dupa header-ul ip din payload-ul pachetului.
	char payload_copy[64];
	memcpy(&payload_copy, (void *)iph + sizeof(struct iphdr), 64);
	// Pun header-ul icmp dupa cel ip.
	memcpy((void *)iph + sizeof(struct iphdr), &icmp, sizeof(struct icmphdr));
	// Pun cei 64 de octeti dupa header-ul icmp.
	memcpy((void *)iph + sizeof(struct iphdr) + sizeof(struct icmphdr), &payload_copy, 64);
	// Setez protocolul pe 1 (icmp) si lungimea pe cele doua headere si cei 64 de octeti.
	iph->protocol = 1;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
	// Interschimb adresele ip sursa si destinatie.
	uint32_t aux = iph->daddr;
	iph->daddr = iph->saddr;
	iph->saddr = aux;
	// Setez ttl-ul pe 64 si calculez checksum-ul ip-ului.
	iph->ttl = 64;
	iph->check = 0;
	iph->check = ip_checksum((void *)iph, sizeof(struct iphdr));
}
/**
 * compare_mac - Functie care compara doua adrese MAC.
 * @m1 - prima adresa MAC
 * @m2 - a doua adresa MAC
 * return - 1 daca adresele sunt egale, 0 altfel.
 */
int compare_mac(uint8_t *m1, uint8_t* m2)
{
	for (int i = 0; i < 6; i++) {
		if (m1[i] != m2[i])
			return 0;
	}
	return 1;

}
/**
 * send_packet_arp - Functie care construieste un pachet ARP si il trimite.
 * @arp_op - tipul arp-ului (request sau reply)
 * @daddr - adresa ip destinatie
 * @saddr - adresa ip sursa
 * @sha - adresa MAC sursa
 * @dha - adresa MAC destinatie
 * @interface - ionterfata pe care trebuie trimis pachetul
 */
void send_packet_arp(uint16_t arp_op, uint32_t daddr, uint32_t saddr,
	uint8_t* sha, uint8_t* dha, int interface)
{
	// Contruiesc un nou pachet si ii setez bitii pe 0.
	packet arp_packet;
	char* payload = arp_packet.payload;
	memset(payload, 0, 1600);
	// Contruiect header-ul de ethernet.
	struct ether_header eth;
	memcpy(&eth.ether_shost, sha, 6);
	memcpy(&eth.ether_dhost, dha, 6);
	eth.ether_type = htons(0x0806);
	// Pun in payload header-ul de ethernet.
	memcpy(payload, &eth, sizeof(struct ether_header));
	payload = payload + sizeof(struct ether_header);
	// Contruiesc header-ul arp.
	struct arp_header arp;
	arp.htype = htons(1);
	arp.ptype = htons(0x0800);
	arp.op = arp_op;
	arp.hlen = 6;
	arp.plen = 4;
	memcpy(arp.sha, sha, 6);
	memcpy(arp.tha, dha, 6);
	arp.spa = saddr;
	arp.tpa = daddr;
	// Pun in payloadd header-ul arp.
	memcpy(payload, &arp, sizeof(struct arp_header));
	arp_packet.len = sizeof(struct arp_header) + sizeof(struct ether_header);
	// Setez interfata si trimit pachetul.
	arp_packet.interface = interface;
	send_packet(&arp_packet);
}
/**
 * incremental_checksum - Functie care calculeaza checksum-ul unui header ip in mod incremental.
 * @prev_checksum - vechiul checksum
 * @prev_ttl - vechiul ttl
 * @new_ttl - noul ttl
 * return - noul checksum
 */
uint16_t incremental_checksum(uint16_t prev_checksum, uint16_t prev_ttl, uint16_t new_ttl)
{
	return ~(~prev_checksum + ~prev_ttl + new_ttl) - 1;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);
	// Aloc memorie pentru tabela de rutare.
	struct route_table_entry* rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "rtable memory");
	// Aloc memorie pentru tabela de arp, pe care urmeaza sa o populez.
	struct arp_entry* arp_table = malloc(sizeof(struct arp_entry) * 100);
	DIE(arp_table == NULL, "arp_table memory");
	// Citesc tabela de rutare.
	int rtable_len = read_rtable(argv[1], rtable);
	// Creez trie-ul, pe care il voi folosi pentru a cauta eficient in tabela de rutare.
	node* trie = create_node(NULL);
	// Populez trie-ul.
	for (int i = 0; i < rtable_len; i++) {
		add_route(trie, &rtable[i], ntohl(rtable[i].mask), ntohl(rtable[i].prefix));
	}

	int arp_table_len = 0;
	// Creez coada de pachete.
	queue packet_queue = queue_create();
	// Retin intr-o variabila adresa de broadcast.
	uint8_t broadcast[6];
	hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		// Preiau header-ul de ethernet.
		struct ether_header *eth = (struct ether_header *) m.payload;
		// Verific daca pachetul este de tip IPv4.
		if (ntohs(eth->ether_type) == 0x0800) {
			// Preiau header-ul de ip si pe cel de icmp (daca exista).
			struct iphdr* iph = ((void *) eth) + sizeof(struct ether_header);
			struct icmphdr* icmp = ((void *) iph) + sizeof(struct iphdr);
			// Obtin adresa MAC pe care a venit pachetul.
			uint8_t curr[6];
			get_interface_mac(m.interface, curr);
			// Verific daca pachetul a fost receptionat corect (este pentru acest router).
			if (compare_mac(curr, eth->ether_dhost)) {
				// Verific daca pachetul este de tip icmp.
				if (iph->protocol == 1) {
					// Verific daca icmp-ul este de tip echo request, si daca este pentru acest router.
					if (icmp->type == 8 && iph->daddr == inet_addr(get_interface_ip(m.interface))) {
						// Setez tipul icmp-ului pe 0 (echo reply).
						icmp->type = 0;
						// Interschimb adresele ip pentru sursa si destinatie.
						uint32_t aux = iph->saddr;
						iph->saddr = iph->daddr;
						iph->daddr = aux;
						// Interschimb adresele MAC pentru sursa si destinatie.
						memcpy(curr, eth->ether_dhost, 6);
						memcpy(eth->ether_dhost, eth->ether_shost, 6);
						memcpy(eth->ether_shost, curr, 6);
						// Calculez checksum-ul pentru header-ul icmp.
						icmp->checksum = 0;
						icmp->checksum = icmp_checksum((void *)icmp, sizeof(struct icmphdr));
						// Setez ttl-ul pachetului la 64 si ii recalculez checksum-ul ip-ului.
						uint16_t prev_ttl = iph->ttl;
						iph->ttl = 64;
						iph->check = incremental_checksum(iph->check, prev_ttl, iph->ttl);
						// Trimit pachetul.
						send_packet(&m);
						continue;
					}
				}
				// Altfel, verific daca checksum-ul pachetului este corect.
				if (ip_checksum((void *) iph, sizeof(struct iphdr)) != 0)
					continue;
				// Daca ttl-ul pachetului este 1 sau 0, trebuie aruncat si
				// trimis un pachet de tip icmp cu mesajul time exceeded.
				if ((iph->ttl == 1) | (iph->ttl == 0)) {
					// Pregatesc header-ul icmp si il pun in pachet.
					prepare_icmp(iph, 11);
					// Actualizez lungimea pachetului.
					m.len = sizeof(struct ether_header) + iph->tot_len;
					// Interschimb adresele MAC pentru sursa si destinatie.
					uint8_t prev[6];
					memcpy(prev, eth->ether_dhost, 6);
					memcpy(eth->ether_dhost, eth->ether_shost, 6);
					memcpy(eth->ether_shost, prev, 6);
					// Trimit pachetul.
					send_packet(&m);
					continue;
				}
				// Daca ttl-ul este corect, caut ruta pe care trebuie sa trimit pachetul.
				struct in_addr dest_ip;
				dest_ip.s_addr = iph->daddr;

				struct route_table_entry* route = (struct route_table_entry *)
				search_route(trie, ntohl(dest_ip.s_addr), NULL);
				// Daca nu am gasit o ruta, inseamna ca nu se poate ajunge
				// la host si trebuie sa trimit un pachet icmp cu mesajul host unreachable.
				if (route == NULL) {
					// Pregatesc header-ul icmp si il pun in pachet.
					prepare_icmp(iph, 3);
					// Actualizez lungimea pachetului.
					m.len = sizeof(struct ether_header) + iph->tot_len;
					// Interschimb adresele MAC pentru sursa si destinatie.
					uint8_t prev[6];
					memcpy(prev, eth->ether_dhost, 6);
					memcpy(eth->ether_dhost, eth->ether_shost, 6);
					memcpy(eth->ether_shost, prev, 6);
					// Trimit pachetul.
					send_packet(&m);
					continue;
				}
				// Daca am gasit o ruta, trebuie sa caut adresa MAC a
				// next_hop-ului.
				struct in_addr next_hop;
				next_hop.s_addr = route->next_hop;
				
				struct arp_entry* arp = get_arp_entry(next_hop, arp_table, arp_table_len);
				// Daca nu o gasesc inseamna ca trebuie sa trimit un ARP request.
				if (arp == NULL) {
					// Pregatesc pachetul pentru a fi trimis (fara adresa MAC
					// destinatie, pe care nu o stiu).
					uint16_t prev_ttl = iph->ttl;
					iph->ttl--;
					// Calculez checksum-ul folosind metoda incrementala.
					iph->check = incremental_checksum(iph->check, prev_ttl, iph->ttl);

					get_interface_mac(route->interface, eth->ether_shost);
					m.interface = route->interface;
					// Aloc memorie pentru o intrare noua in coada.
					struct unsent* unsent = malloc(sizeof(struct unsent));
					memcpy(&unsent->p, &m, sizeof(packet));
					unsent->ip = route->next_hop;
					// Adaug in coada.
					queue_enq(packet_queue, unsent);
					// Construiesc un nou pachet de tip ARP request, pe care il trimit pe broadcast.
					send_packet_arp(htons(1), route->next_hop,
						inet_addr(get_interface_ip(m.interface)), eth->ether_shost,
						broadcast, route->interface);
					continue;
				}
				// In caz ca am gasit adresa MAC destinatie, pot actualiza pachetul si sa il trimit.
				uint16_t prev_ttl = iph->ttl;
				iph->ttl--;
				// Calculez checksum-ul folosind metoda incrementala.
				iph->check = incremental_checksum(iph->check, prev_ttl, iph->ttl);

				memcpy(eth->ether_dhost, arp->mac, 6);
				get_interface_mac(route->interface, eth->ether_shost);

				m.interface = route->interface;
				send_packet(&m);
			}
		}
		// Verific daca pachetul este de tip ARP.
		if (ntohs(eth->ether_type) == 0x0806) {
			// Preiau header-ul de ARP.
			struct arp_header* arp = ((void *) eth) + sizeof(struct ether_header);
			// Verific daca pachetul a fost trimis pe broadcast.
			if (compare_mac(eth->ether_dhost, broadcast)) {
				// Verific daca pachetul ARP este de tip request.
				if (ntohs(arp->op) == 1) {
					// Verific daca pachetul este pentru acest router.
					if (arp->tpa == inet_addr(get_interface_ip(m.interface))) {
						// Obtin adresa MAC a router-ului.
						uint8_t reply_mac[6];
						get_interface_mac(m.interface, reply_mac);
						// Construiesc un nou pachet de tip ARP reply,
						// pe care il trimit de unde a venit.
						send_packet_arp(htons(2), arp->spa, arp->tpa, reply_mac,
							eth->ether_shost, m.interface);
					}
				}
			} else {
				if (ntohs(arp->op) == 2) {
					// Daca pachetul nu a fost trimis pe broadcast, verific daca
					// este de tip reply si daca este pentru mine.
					if (arp->tpa == inet_addr(get_interface_ip(m.interface))) {
						// Verific daca am nevoie de adresa MAC din pachetul ARP.
						int needed = 1;
						for (int i = 0; i < arp_table_len; i++) {
							if (arp->spa == arp_table[i].ip)
								needed = 0;
						}
						// Daca am nevoie, o adaug in tabela arp.
						if (needed) {
							arp_table[arp_table_len].ip = arp->spa;
							memcpy(&arp_table[arp_table_len].mac, arp->sha, 6);
							arp_table_len++;
							// Trebuie sa parcurg coada, ceea ce se poate face doar
							// prin golirea ei si construirea unei cozi noi.
							queue new_queue = queue_create();
							while (!queue_empty(packet_queue)) {
								// Extrag un element din coada.
								struct unsent* unsent = queue_deq(packet_queue);
								// Daca pachetul extras trebuie trimis pe noua adresa obtinuta
								// trimit pachetul.
								if (unsent->ip == arp->spa) {
									// Setez adresa MAC destinatie.
									struct ether_header* eth_hdr = ((void *) unsent->p.payload);
									memcpy(eth_hdr->ether_dhost, arp->sha, 6);
									send_packet(&unsent->p);
									// Eliberez memoria ocupata de elementul din coada.
									free(unsent);
								// Altfel readaug pachetul in noua coada.
								} else {
									queue_enq(new_queue, unsent);
								}
							}
							// Eliberez memoria coadei precedente.
							free(packet_queue);
							// Schimb adresa la care pointeaza coada spre noua coada.
							packet_queue = new_queue;
						}
					}
				}
			}
		}
	}
}
