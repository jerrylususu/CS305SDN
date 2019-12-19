
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


    # def flood(self, now):
    #     for edge in self.tree:
    #         if edge.u[0] == now:
    #             for data in self._dfs(edge.v[0], now, edge.u[1]):
    #                 yield data
    #         if edge.v[0] == now:
    #             for data in self._dfs(edge.u[0], now, edge.v[1]):
    #                 yield data

    def flood(self, now, fa, port):
        yield fa, now, port
        for edge in self.tree:
            if edge.u[0] == now:
                if edge.v[0] == fa:
                    continue
                for data in self.flood(edge.v[0], now, edge.u[1]):
                    yield data
            if edge.v[0] == now:
                if edge.u[0] == fa:
                    continue
                for data in self.flood(edge.u[0], now, edge.v[1]):
                    yield data

if __name__ == "__main__":
    st = SpanningTree(100)
    st.add(Edge(1, 1, 2, 1))
    st.add(Edge(1, 2, 5, 1))
    st.add(Edge(2, 3, 4, 1))
    st.add(Edge(4, 2, 5, 2))
    st.add(Edge(3, 1, 2, 2))

    st.work()

    for edge in st.flood(3, None, None):
        print(f"to={edge[1]}, last_switch={edge[0]}, last_port={edge[2]}")
