#!/usr/bin/env python3

"""Shortest Path Switching template
CSCI1680

This example creates a simple controller application that watches for
topology events.  You can use this framework to collect information
about the network topology and install rules to implement shortest
path switching.

"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0

from ryu.topology import event, switches
import ryu.topology.api as topo

from ryu.lib.packet import packet, ether_types
from ryu.lib.packet import ethernet, arp, icmp

from ofctl_utils import OfCtl, VLANID_NONE

from topo_manager_example import TopoManager

import ryu.app.ofctl.api as ofctl_api

from ryu.lib.mac import haddr_to_bin

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__


class Edge(object):
    def __init__(self, u, port_u, v, port_v):
        self.u = (u, port_u)
        self.v = (v, port_v)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "==> u: (%d %d) v: (%d %d)" % (self.u[0], self.u[1], self.v[0], self.v[1])

    def __eq__(self, other):
        return self.u == other.u and self.v == other.v


class SpanningTree():
    def __init__(self, n):
        self.edges = []
        self.tree = []
        self.n = n
        self.fa = []

    def add(self, edge):
        self.edges.append(edge)

    def remove(self, edge):
        self.edges.remove(edge)

    def reset_tree(self):
        self.tree.clear()

    def init_fa(self):
        self.fa = [x for x in range(self.n)]

    def get_fa(self, x):
        if self.fa[x] == x:
            return x
        self.fa[x] = self.get_fa(self.fa[x])
        return self.fa[x]

    def work(self):
        self.tree = []
        self.init_fa()
        for edge in self.edges:
            fu = self.get_fa(edge.u[0])
            fv = self.get_fa(edge.v[0])
            if fu == fv:
                continue
            self.fa[fu] = fv
            self.tree.append(edge)

    def __iter__(self):
        for x in self.tree:
            yield x

    def flood(self, now):
        queue = [[(now, None)], []]
        t = 0
        while len(queue[t]) > 0:
            res = []
            for now, fa in queue[t]:
                for edge in self.tree:
                    v = None
                    if edge.u[0] == now:
                        u, v = edge.u, edge.v
                    if edge.v[0] == now:
                        u, v = edge.v, edge.u
                    if v is None or v[0] == fa:
                        continue

                    res.append((u[0], u[1], v[0]))
                    queue[t ^ 1].append((v[0], u[0]))

            yield res
            queue[t] = []
            t ^= 1


class Graph:
    def __init__(self, n):
        self.n = n

        self.to = []
        self.next = []
        self.port = []
        self.exist = []

        self.head = [0] * n

    def add(self, u, v, port):
        self.to.append(v)
        self.next.append(self.head[u])
        self.port.append(port)
        self.exist.append(True)

        self.head[u] = len(self.next) - 1

    def go_from(self, u):
        now = self.head[u]
        while now != 0:
            if self.exist[now] == False:
                now = self.next[now]
                continue
            yield self.to[now], self.port[now]
            now = self.next[now]

    def remove(self, u, v):
        now = self.head[u]
        while now != 0:
            if self.exist[now] == False:
                now = self.next[now]
                continue
            if self.to[now] == v:
                self.exist[now] = False
            now = self.next[now]


class ShortestPathSwitching(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShortestPathSwitching, self).__init__(*args, **kwargs)

        self.tm = TopoManager()
        self.graph = Graph(100)  # switch 数量
        self.belong = {}  # 每个host属于哪个switch: key, value <- host_mac, (switch_id, switch_port_num)
        self.mac_to_port = {}  # ???
        self.res = {}  # 最短路结果: key, value <- [i][j] = (i-> out1_port)
        self.ip_mac_dict = {}  # 每个ip对应的host是什么：key, value <- ip, host_mac
        self.switch_list = []  # 所有switch的list
        # self.datapath_set = {}

        self.spanning_tree = SpanningTree(1000);  # 用于处理广播包的伸展树 只处理内部switch节点
        self.switch_contain_host = {}  # 每个switch有哪些host: key=switch.dp.id, value=[] (host_mac, switch_port_num)

    def show_topology(self):
        print("=========== XCC Graph ============")
        print("Src SID\tPort\tDst SID")
        # print(self.switch_contain_host)
        for u in self.switch_contain_host:
            s = set()
            for v, port in self.graph.go_from(u):
                if v not in s:
                    s.add(v)
                    print(f"{u}\t{port}\t{v}")
        print("")
        print("")
        print("SID\tPort\tHost")
        for u in self.switch_contain_host:
            for item in self.switch_contain_host[u]:
                print(f"{u}\t{item[1]}\t{item[0]}")
        print("============= Done ===============")

    def show_shortest_path(self):
        print("=========== XCC Path =============")
        try:
            for u in self.switch_list:
                for v in self.switch_list:
                    paths = []
                    now = u.dp.id
                    while now != v.dp.id:
                        port = self.res[now][v.dp.id]
                        p = None
                        for t, tp in self.graph.go_from(now):
                            if tp != port:
                                continue
                            p = t
                            break
                        assert p is not None
                        now = p
                        paths.append((port, p))
                    res = f"s{u.dp.id}"
                    for path in paths:
                        res += f" -p{path[0]}-> s{path[1]}"
                    print(res)
        except KeyError:
            pass
        print("============= Done ===============")

    def show_spanning_tree(self):
        print("=========== XCC Tree =============")
        try:
            for u in self.switch_list:
                last_ids = set()
                for edge_layers in self.spanning_tree.flood(u.dp.id):
                    for edge in edge_layers:
                        try:
                            last_ids.remove(edge[0])
                        except KeyError as e:
                            pass
                        print(f"tree_root=s{u.dp.id}: s{edge[0]} -p{edge[1]}-> s{edge[2]}")
                # break
        except KeyError:
            pass
        print("============= Done ===============")

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """
        switch = ev.switch

        self.logger.warn("Added Switch switch%d with ports:", switch.dp.id)
        for port in switch.ports:
            self.logger.warn("\t%d:  %s", port.port_no, port.hw_addr)

        self.tm.add_switch(switch)
        self.switch_list.append(switch)  # 加入controller控制的switch列表

        # switch上线 加入mapping 为之后链路做准备
        self.one_switch_special_case()

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):  # switch下线
        """
        Event handler indicating a switch has been removed
        """
        switch = ev.switch

        self.logger.warn("Removed Switch switch%d with ports:", switch.dp.id)
        for port in switch.ports:
            self.logger.warn("\t%d:  %s", port.port_no, port.hw_addr)

        try:
            self.switch_list.remove(switch)  # 移除controller控制的switch列表
        except ValueError:
            # 应该已经被移除了
            pass

        self.one_switch_special_case()

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):  # 主机上线
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """
        host = ev.host

        self.logger.warn("Host Added:  %s (IPs:  %s) on switch%s/%s (%s)",
                         host.mac, host.ipv4,
                         host.port.dpid, host.port.port_no, host.port.hw_addr)

        # 1 记录这个主机对应的switch 增加转发表
        # 相当于终端
        self.belong[host.mac] = (host.port.dpid, host.port.port_no)
        self.add_forwaring_rule(
            ofctl_api.get_datapath(self, dpid=host.port.dpid),
            host.mac,
            host.port.port_no
        )

        # 2 更新其他switch上的转发表
        for dpid in self.res:  # 最短路的计算结果？
            dp = ofctl_api.get_datapath(self, dpid=dpid)

            # 如果是自己 就跳过
            if dpid == host.port.dpid:
                continue

            # 从图上更新其他switch
            self.add_forwaring_rule(
                dp,
                host.mac,
                self.res[dpid][host.port.dpid]
            )

        # JL: 增加ip-mac对应
        self.ip_mac_dict[host.ipv4[0]] = host.mac

        self.tm.add_host(host)

        # 增加switch-host记录
        print("[DEBUG ADD] add switch-host before", (host.port.dpid not in self.switch_contain_host))
        if host.port.dpid not in self.switch_contain_host:
            # 如果这个host相连的switch还没有被记录过
            self.switch_contain_host[host.port.dpid] = []

        self.switch_contain_host[host.port.dpid].append((host.mac, host.port.port_no))

        print("[BELONG]", self.belong)

        self.calc_spanning_tree()

        self.one_switch_special_case()

        self.show_topology()
        self.show_shortest_path()
        self.show_spanning_tree()

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Event handler indicating a link between two switches has been added
        """
        link = ev.link
        src_port = ev.link.src
        dst_port = ev.link.dst
        self.logger.warn("Added Link:  switch%s/%s (%s) -> switch%s/%s (%s)",
                         src_port.dpid, src_port.port_no, src_port.hw_addr,
                         dst_port.dpid, dst_port.port_no, dst_port.hw_addr)

        # 链路上线 更新内部图
        self.graph.add(src_port.dpid, dst_port.dpid, src_port.port_no)
        self.graph.add(dst_port.dpid, src_port.dpid, dst_port.port_no)
        # 更新最短路结果
        self.shortest_path()

        # 链路上线 更新内部伸展树
        # 只用更新单向边
        self.spanning_tree.add(Edge(src_port.dpid, src_port.port_no, dst_port.dpid, dst_port.port_no))

        # 更新伸展树结果
        self.spanning_tree.reset_tree()
        self.spanning_tree.work()

        # 全部flow清空
        self.flow_reset()

        # 重建 flow
        self.flow_recreate()

        # print("[DEBUG!!!] self.switch_contain_host", self.switch_contain_host)
        # 上层伸展树
        self.calc_spanning_tree()

        self.show_topology()
        self.show_shortest_path()
        self.show_spanning_tree()


    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        link = ev.link
        src_port = link.src
        dst_port = link.dst

        print("[*] delete happened")
        self.logger.warn("Deleted Link:  switch%s/%s (%s) -> switch%s/%s (%s)",
                         src_port.dpid, src_port.port_no, src_port.hw_addr,
                         dst_port.dpid, dst_port.port_no, dst_port.hw_addr)

        # 更新内部最短路
        self.graph.remove(src_port.dpid, dst_port.dpid)
        self.graph.remove(dst_port.dpid, src_port.dpid)
        self.shortest_path()

        # 链路下线 更新内部伸展树
        # 只用更新单向边
        self.spanning_tree.remove(Edge(src_port.dpid, src_port.port_no, dst_port.dpid, dst_port.port_no))

        # 更新伸展树结果
        self.spanning_tree.reset_tree()
        self.spanning_tree.work()

        # 全部flow清空
        self.flow_reset()

        # 重建 flow
        self.flow_recreate()

        # 上层伸展树
        self.calc_spanning_tree()

        self.show_topology()
        self.show_shortest_path()
        self.show_spanning_tree()


    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        port = ev.port
        self.logger.warn("Port Changed:  switch%s/%s (%s):  %s",
                         port.dpid, port.port_no, port.hw_addr,
                         "UP" if port.is_live() else "DOWN")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # 如果收到 PacketIn 请求
        pass

    def shortest_path(self):
        self.res = {}
        for i in range(self.graph.n):
            queue = [i]
            dis = [1000] * self.graph.n
            inq = [False] * self.graph.n

            dis[i] = 0
            inq[i] = True
            while len(queue) != 0:
                u = queue[0]
                for v, port in self.graph.go_from(u):
                    if dis[v] > dis[u] + 1:
                        dis[v] = dis[u] + 1
                        if not inq[v]:
                            queue.append(v)
                inq[u] = False
                del queue[0]

            for j in range(self.graph.n):
                for v, port in self.graph.go_from(j):
                    if dis[v] + 1 == dis[j]:
                        if j in self.res:
                            self.res[j][i] = port
                        else:
                            self.res[j] = {}
                            self.res[j][i] = port
        print("[!!!!]", self.res)

    def one_switch_special_case(self):
        # 只有一个 switch 的时候 没有生成树
        if (len(self.switch_list) == 1):
            for switch in self.switch_list:
                for host_mac in self.belong:
                    host_port_dpid, host_port_no = self.belong[host_mac]
                    datapath = ofctl_api.get_datapath(self, dpid=host_port_dpid)
                    match = datapath.ofproto_parser.OFPMatch(
                        dl_dst=haddr_to_bin(ETHERNET_MULTICAST),  # 这是一个广播包
                        dl_src=haddr_to_bin(host_mac),  # 来源 MAC 地址
                    )
                    actions = [datapath.ofproto_parser.OFPActionOutput(i[1]) for i in
                               self.switch_contain_host[host_port_dpid]]

                    ofp_parser = datapath.ofproto_parser

                    flow_mod = datapath.ofproto_parser.OFPFlowMod(
                        datapath, match=match, cookie=0, priority=50, actions=actions)
                    datapath.send_msg(flow_mod)

    def flow_reset(self):
        # flow 清空
        for switch in self.switch_list:
            datapath = ofctl_api.get_datapath(self, dpid=switch.dp.id)
            empty_match = datapath.ofproto_parser.OFPMatch()
            cmd = datapath.ofproto.OFPFC_DELETE
            actions = []

            ofp_parser = datapath.ofproto_parser

            flow_mod = datapath.ofproto_parser.OFPFlowMod(
                datapath, match=empty_match, cookie=0, command=cmd, priority=65535, actions=actions)
            datapath.send_msg(flow_mod)

    def flow_recreate(self):
        # flow 重建
        for host_mac in self.belong:
            host_port_dpid, host_port_no = self.belong[host_mac]
            self.add_forwaring_rule(
                ofctl_api.get_datapath(self, dpid=host_port_dpid),
                host_mac,
                host_port_no
            )

            for dpid in self.res:  # 最短路的计算结果？
                dp = ofctl_api.get_datapath(self, dpid=dpid)

                # 如果是自己 就跳过
                if dpid == host_port_dpid:
                    continue

                # 从图上更新其他switch
                self.add_forwaring_rule(
                    dp,
                    host_mac,
                    self.res[dpid][host_port_dpid]
                )

    def calc_spanning_tree(self):
        # 广播包应该也到当前节点的内部节点！！！！！
        for switch in self.switch_contain_host:
            current_id = switch

            # if current_id in self.switch_contain_host:
            #     # 当前switch是边界switch
            #     # 可以设定内部switch
            # else:
            #     # 当前switch是内部switch
            # if current_id in self.switch_contain_host:

            for (host_mac, switch_port_num) in self.switch_contain_host[current_id]:

                print("[^] processing on ", host_mac, current_id)

                last_ids = set()

                for edge_layers in self.spanning_tree.flood(current_id):
                    print("[>>]", edge_layers)
                    if len(edge_layers) > 0:  # 只设定有子结点的

                        for edge in edge_layers:
                            try:
                                last_ids.remove(edge[0])
                            except KeyError as e:
                                print("[^] already removed ", edge[0])
                            print("[$$$]", "from=", current_id, "to=", edge[2], "last_switch=", edge[0], "last_port=",
                                  edge[1])
                            last_ids.add(edge[2])

                        # 预处理 按照父节点分类
                        # edge: father, father_out_port, son
                        out_port_dict = {}
                        for edge in edge_layers:
                            if edge[0] not in out_port_dict:
                                out_port_dict[edge[0]] = []
                            out_port_dict[edge[0]].append((edge[1], edge[2]))

                        for father in out_port_dict:

                            datapath = ofctl_api.get_datapath(self, dpid=father)
                            ofproto = datapath.ofproto
                            match = datapath.ofproto_parser.OFPMatch(
                                dl_dst=haddr_to_bin(ETHERNET_MULTICAST),  # 这是一个广播包
                                dl_src=haddr_to_bin(host_mac),  # 来源 MAC 地址
                            )

                            new_out_ports = [i[0] for i in out_port_dict[father]]

                            if father in self.switch_contain_host:
                                host_out_li = [i[1] for i in self.switch_contain_host[father]]
                                new_out_ports += host_out_li

                            actions = [datapath.ofproto_parser.OFPActionOutput(i) for i in new_out_ports]

                            mod = datapath.ofproto_parser.OFPFlowMod(
                                datapath=datapath, match=match, cookie=0,
                                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                                priority=1,  # 优先级至少比默认最短路优先级高 (或许可以设定一个统一值)
                                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
                            datapath.send_msg(mod)

                print("[^] terminals: ", last_ids)

                for terminal_id in last_ids:
                    # 终端的话 发给对应的host就好了
                    if terminal_id in self.switch_contain_host:
                        datapath = ofctl_api.get_datapath(self, dpid=terminal_id)
                        ofproto = datapath.ofproto
                        match = datapath.ofproto_parser.OFPMatch(
                            dl_dst=haddr_to_bin(ETHERNET_MULTICAST),  # 这是一个广播包
                            dl_src=haddr_to_bin(host_mac),  # 来源 MAC 地址
                        )

                        host_out_li = [i[1] for i in self.switch_contain_host[terminal_id]]
                        actions = [datapath.ofproto_parser.OFPActionOutput(i) for i in host_out_li]

                        mod = datapath.ofproto_parser.OFPFlowMod(
                            datapath=datapath, match=match, cookie=0,
                            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                            priority=1,  # 优先级至少比默认最短路优先级高 (或许可以设定一个统一值)
                            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
                        datapath.send_msg(mod)

    def add_forwaring_rule(self, datapath, dl_dst, port):
        ofctl = OfCtl.factory(datapath, self.logger)

        actions = [datapath.ofproto_parser.OFPActionOutput(port)]

        ofctl.set_flow(cookie=0, priority=100, dl_vlan=VLANID_NONE, dl_dst=dl_dst, actions=actions)

    def delete_forwarding_rule(self, datapath, dl_dst):
        ofctl = OfCtl.factory(datapath, self.logger)

        match = datapath.ofproto_parser.OFPMatch(dl_dst=dl_dst)

        ofctl.delete_flow(cookie=0, priority=0, match=match)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=5, hard_timeout=15,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
