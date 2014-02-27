
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/gfp.h>
#include <linux/types.h>

#include <linux/inet.h>
#include <net/inet_sock.h>
#include <net/tcp.h>


//module pararm 
char* dip=0;
int dport=0;

module_param(dip, charp, 0444);
MODULE_PARM_DESC(dip, "dst ipaddr");
module_param(dport, int, 0444);
MODULE_PARM_DESC(dport, "dst port");


int k_dip=0;
int k_dport=0;
 
int g_monitor_back=0;
struct request_sock * g_monitor_rqs=NULL;
int g_monitor_syn=0;
int g_monitor_alloc=0;
int	g_monitor_hnd =0;
int	g_monitor_estab=0;
int	g_monitor_proc=0;

/*
syn

dst addr ,port 
*/
int match_taget(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);

	if (th->syn == 0 )
	{
		return 0; 
	}

	if (iph->daddr ==k_dip )
	{
		if (ntohs(th->dest) == k_dport)
		{
			return 1;
		}
	}

	return 0;
}

int match_target_syn_reply(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);

    //notice 2 kind packets: syn+ack, rst+ack 
	if (!th->ack)
		return 0;
	if (! ( th->syn  || th->rst ) )
		return 0;

	if (iph->saddr ==k_dip )
	{
		if (ntohs(th->source) == k_dport)
		{
			return 1;
		}
	}

	return 0;
}


void print_skb_tuple(struct sk_buff*skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
#if 0
	printk("sip=%d.%d.%d.%d %d sport=%d,dip=%d.%d.%d.%d %d dport=%d\n",
		    NIPQUAD(iph->saddr),iph->saddr,ntohs(th->source),
			    NIPQUAD(iph->daddr),iph->daddr,ntohs(th->dest)
		  );
#endif 
	printk("sip=%d.%d.%d.%d sport=%d,dip=%d.%d.%d.%d dport=%d\n",
		    NIPQUAD(iph->saddr),ntohs(th->source),
			NIPQUAD(iph->daddr),ntohs(th->dest)
		  );
}



void jtcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);

	g_monitor_syn =0;
	g_monitor_back=0;//reset
	g_monitor_rqs =0; 

	if (!match_taget(skb))
	{
		goto out;
	}


	g_monitor_syn =1;

	printk("%s syn seq=0x%x ack_seq=0x%x syn=%d rst=%d,st=%d,cerr=%d\n",
			__FUNCTION__,
			ntohl(th->seq),
			ntohl(th->ack_seq),
			th->syn,
			th->rst,
			sk->sk_state,
	 		(skb->len < tcp_hdrlen(skb) || tcp_checksum_complete(skb))
		   );

out:
	jprobe_return();
	return ;

}


void jtcp_child_process(struct sock *parent, struct sock *child,
              struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	if (!match_taget(skb))
	{
		goto out;
	}
	printk("%s add skb seq=0x%x\n",__FUNCTION__,
			ntohl( th->seq)
		  );

	if (sock_owned_by_user(child))
	{
		printk("%s add skb seq=0x%x into backlog!!\n",__FUNCTION__,
				ntohl( th->seq)
			  );
		g_monitor_back=1;
	}
out:
	jprobe_return();
	return ;

}

void jtcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	if (!match_taget(skb))
	{
		goto out;
	}


	if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
	{
		printk("%s skb seq=0x%x route flags issue.\n",__FUNCTION__,
			ntohl(th->seq));
	}

	
	printk("%s seq=0x%x acceptq=%d,reqskq=%d,young=%d,isn=0x%x\n",
				__FUNCTION__,
				ntohl(th->seq),
				sk_acceptq_is_full(sk),
				inet_csk_reqsk_queue_is_full(sk),
				(inet_csk_reqsk_queue_young(sk) > 1),
				TCP_SKB_CB(skb)->when		
		  );

	

out:
	jprobe_return();
	return ;
}

void jsecurity_inet_conn_request(struct sock *sk, 
            struct sk_buff *skb, struct request_sock *req)
{
	struct tcphdr *th = tcp_hdr(skb);
	if (!match_taget(skb))
	{
		goto out;
	}
	g_monitor_rqs = req;
	printk("%s req %p in seq=0x%x\n",__FUNCTION__, req,
		ntohl(th->seq));
out:
	jprobe_return();
	return ;
}


void jinet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
                   unsigned long timeout)
{
	if (g_monitor_rqs)
	printk("%s req isn=0x%x\n",__FUNCTION__, 
			tcp_rsk(req)->snt_isn
			);

	
	jprobe_return();
	return ;

}

void j__kfree_skb(struct sk_buff *skb )
{
	struct tcphdr *th = tcp_hdr(skb);

	if (!match_taget(skb))
	{
		goto out;
	}

	if (g_monitor_back || (g_monitor_estab==0 && g_monitor_hnd==0 && g_monitor_proc==0))	
	{
		dump_stack();
	}

	printk("%s syn packet syn=%d seq=0x%x ack_seq=0x%x %d %d %d %d %d\n",
			__FUNCTION__,
			th->syn,ntohl(th->seq),ntohl(th->ack_seq),
			g_monitor_syn,
			g_monitor_back,
			g_monitor_estab,
			g_monitor_hnd,
			g_monitor_proc
			);

	g_monitor_syn =0;
	g_monitor_back=0;
	g_monitor_hnd =0;
	g_monitor_estab=0;
	g_monitor_proc=0;
	
	
out:
	jprobe_return();
}




void jip_local_out(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);

	if (!match_target_syn_reply(skb))
	{
		goto out;
	}
	printk("%s seq=0x%x ack_seq=0x%x,syn=%d rst=%d\n",
			__FUNCTION__,ntohl(th->seq),ntohl(th->ack_seq),
			th->syn,
			th->rst);
	print_skb_tuple(skb);

//    printk("%s output func=%p\n",__FUNCTION__,skb_dst(skb)->output);
out:
	jprobe_return();
	return;
}

void jdev_queue_xmit(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);

	if (!match_target_syn_reply(skb))
	{
		goto out;
	}

	printk("%s seq=0x%x ack_seq=0x%x,syn=%d rst=%d from %s\n",
			__FUNCTION__,ntohl(th->seq),ntohl(th->ack_seq),
			th->syn,
			th->rst,
			skb->dev->name);
//	print_skb_tuple(skb);

out:
	jprobe_return();
	return;
}



void jip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
           unsigned int len)
{

	struct tcphdr *reply_th;
	struct tcphdr *th=tcp_hdr(skb);

	if (!match_taget(skb))
	{
		goto out;
	}
	
	reply_th=(struct tcphdr*)arg->iov[0].iov_base;
		
	if (ntohs(reply_th->source) != k_dport)
	{
		goto out;
	}
	if (reply_th->rst!=1)
	{
		goto out;
	}

	printk("%s reset response for seq=0x%x syn=%d\n",__FUNCTION__,
		ntohl(th->seq),th->syn);
out:
	jprobe_return();
	return;

}

void jtcp_check_req(struct sock *sk, struct sk_buff *skb,
               struct request_sock *req,
			                  struct request_sock **prev)
{
	struct tcphdr *th=tcp_hdr(skb);

	if (!match_taget(skb))
	{
		goto out;
	}

	printk("%s for seq=0x%x syn=%d\n",__FUNCTION__,
		ntohl(th->seq),th->syn);

out:
	
	jprobe_return();
	return;
}

void jtcp_rcv_established(struct sock *sk, struct sk_buff *skb,
            struct tcphdr *th, unsigned len)
{
	if (!match_taget(skb))
	{
		goto out;
	}

	g_monitor_estab=1;
	printk("%s seq=0x%x syn=%d\n",__FUNCTION__,
		ntohl(th->seq),th->syn);

out:
	jprobe_return();
	return;
}

void jkmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	g_monitor_alloc=0;

	if (!g_monitor_syn)
		goto out;

	if( (cachep == tcp_prot.rsk_prot->slab) &&( flags==GFP_ATOMIC))
	{
		printk("inet_reqsk_alloc called begin\n");	
		g_monitor_alloc=1;
	}
out:
	jprobe_return();
	return;

}

void jtcp_rcv_state_process(struct sock *sk, struct sk_buff *skb,
              struct tcphdr *th, unsigned len)
{
	if (!match_taget(skb))
	{
		goto out;
	}

	g_monitor_proc=1;
	printk("%s seq=0x%x syn=%d\n",__FUNCTION__,
		ntohl(th->seq),th->syn);
out:
	jprobe_return();
	return;
}

static struct jprobe my_jprobes[] = {
	{
		.entry			= j__kfree_skb,
		.kp = {
			.symbol_name	= "__kfree_skb",
		},
	},
	{
		.entry			= jtcp_v4_do_rcv,
		.kp = {
			.symbol_name	= "tcp_v4_do_rcv",
		},
	},
	{
		.entry			= jip_local_out,
		.kp = {
			.symbol_name	= "ip_local_out",
		},
	},
	{
		.entry			= jdev_queue_xmit,
		.kp = {
			.symbol_name	= "dev_queue_xmit",
		},
	},
	{
		.entry         = jtcp_v4_conn_request,
		.kp = {
			.symbol_name	= "tcp_v4_conn_request",
		},
	},
	{
		.entry         = jip_send_reply,
		.kp = {
			.symbol_name	= "ip_send_reply",
		},
	},
	{
		.entry         = jsecurity_inet_conn_request,
		.kp = {
			.symbol_name	= "security_inet_conn_request",
		},
	},
	{
		.entry         = jinet_csk_reqsk_queue_hash_add,
		.kp = {
			.symbol_name	= "inet_csk_reqsk_queue_hash_add",
		},
	},
	{
		.entry         = jtcp_child_process,
		.kp = {
			.symbol_name	= "tcp_child_process",
		},
	},
	{
		.entry         = jtcp_check_req,
		.kp = {
			.symbol_name	= "tcp_check_req",
		},
	},
	{
		.entry         = jtcp_rcv_established,
		.kp = {
			.symbol_name	= "tcp_rcv_established",
		},
	},
	{
		.entry         = jkmem_cache_alloc,
		.kp = {
			.symbol_name	= "kmem_cache_alloc",
		},
	},
	{
		.entry         = jtcp_rcv_state_process,
		.kp = {
			.symbol_name	= "tcp_rcv_state_process",
		},
	},

};


int ret_tcp_rcv_state_process(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval = regs_return_value(regs);

	if (g_monitor_syn)
	{
		printk("tcp_rcv_state_process returned 0x%x\n",
				retval);
		//dump_stack();
	}

    return 0;
}


int ret_tcp_v4_hnd_req(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	g_monitor_hnd=1;
    unsigned long retval = regs_return_value(regs);
	if (g_monitor_syn)
	{
		if (!retval)
			printk("tcp_v4_hnd_req returned 0,drop syn packet\n");
		else
			printk("tcp_v4_hnd_req returned 0x%x\n", retval);//wrong ,be 0xffff8800 retval
	}

	//g_monitor_syn=0;

    return 0;
}


int ret_kmem_cache_alloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval = regs_return_value(regs);

	if (g_monitor_alloc)
	{
		printk("inet_reqsk_alloc called return 0x%x\n",
				retval
			  );
		g_monitor_alloc=0;
	}

    return 0;
}



struct kretprobe my_kretprobes[]={
	{
		  .handler        = ret_tcp_rcv_state_process,
		  .entry_handler  = NULL,
		  .data_size      = 0,
		  .maxactive      = 20,
		  .kp.symbol_name	= "tcp_rcv_state_process",

	},
	{
		  .handler        = ret_tcp_v4_hnd_req,
		  .entry_handler  = NULL,
		  .data_size      = 0,
		  .maxactive      = 20,
	},
	{
		  .handler        = ret_kmem_cache_alloc,
		  .entry_handler  = NULL,
		  .data_size      = 0,
		  .maxactive      = 20,
		  .kp.symbol_name	= "kmem_cache_alloc",
	},
};

void print_monitor_target(void)
{
	printk("monitor packet: daddr %s->0x%x,dport %d->%d\n",
			dip,k_dip,
			dport,k_dport
		  );
}

int init_module(void)
{
	int ret=0;
	int i=0;
	int j=0;

	for(i=0; i <ARRAY_SIZE(my_jprobes) ; i++)
    {
        if ((ret = register_jprobe(my_jprobes+i)) <0) {
            printk("1 register failed, returned %d\n", ret);
			ret = -1;	
			goto err_i;
        }

        printk("1 registered OK.%d\n",i);
    }

	for(j=0; j <ARRAY_SIZE(my_kretprobes) ; j++)
    {
		if (j==1)
		{
			my_kretprobes[j].kp.addr=0xffffffff81343840;//in sles11sp1
		}

        if ((ret = register_kretprobe(my_kretprobes+j)) <0) {
            printk("2 register failed, returned %d\n", ret);
			ret = -1;	
			goto err_j;
        }

        printk("2 registered OK.%d\n",j);
    }
	
	k_dip= in_aton(dip);
	k_dport= dport;

    print_monitor_target();	
	return 0;

err_j:
	for (j=j-1;j>=0;j--)
	{
		unregister_kretprobe(my_kretprobes+j);
	}
	
err_i:
	for (i=i-1;i>=0;i--)
	{
        unregister_jprobe(my_jprobes+i);
	}

	return ret;
}

void cleanup_module(void)
{
    int i ;
	int j ;

	for (j=ARRAY_SIZE(my_kretprobes)-1;j>=0;j--)
	{
		unregister_kretprobe(my_kretprobes+j);
	}

    for (i=ARRAY_SIZE(my_jprobes)-1; i>=0; i--)
    {
        unregister_jprobe(my_jprobes+i);
    }
    printk("unregistered.OK.\n");
}



MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("trace dropping skb in kernel tcp/ip layer for kernel version >2.6.18");
MODULE_AUTHOR("Jun Hu(jhu@novell.com)");
