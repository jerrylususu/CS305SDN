
class Edge(object):
    def __init__(self, u, port_u, v, port_v):
        self.u = (u, port_u)
        self.v = (v, port_v)

    def __repr__(self):
        return __str__(self)

    def __str__(self):
        return "==> u: (%d %d) v: (%d %d)" % (self.u[0], self.u[1], self.v[0], self.v[1])


class SpanningTree():
    def __init__(self, n):
        self.edges = []
        self.tree = []
        self.n = n
        self.fa = []

    def add(self, edge: Edge):
        self.edges.append(edge)

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


if __name__ == "__main__":
    st = SpanningTree(100)

    st.add(Edge(5, 3, 4, 3))
    st.add(Edge(1, 2, 2, 1))
    st.add(Edge(5, 2, 2, 3))
    st.add(Edge(2, 2, 3, 1))
    st.add(Edge(3, 2, 4, 2))
    st.add(Edge(1, 3, 6, 4))
    st.add(Edge(3, 3, 6, 2))
    st.add(Edge(6, 3, 4, 4))

    st.work()

    for res in st.flood(2):
        for edge in res:
            print(f"to={edge[2]}, last_switch={edge[0]}, last_port={edge[1]}")
