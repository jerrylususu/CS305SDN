class Graph:
    def __init__(self, n):
        self.n = n

        self.to = []
        self.next = []
        self.port = []

        self.head = [0] * n

    def add(self, u, v, port):
        self.to.append(v)
        self.next.append(self.head[u])
        self.port.append(port)

        self.head[u] = len(self.next) - 1

    def go_from(self, u):
        now = self.head[u]
        while now != 0:
            yield self.to[now], self.port[now]
            now = self.next[now]    



Class T:

    def __init__(self):
        self.graph = Graph(100)
        self.res = {}

    def shortest_path(self):
        '''
        最短路计算
        '''
        self.res = {}
        for i in range(self.graph.n):
            queue = [i]
            dis = [(1e9, -1)] * self.graph.n
            inq = [False] * self.graph.n

            dis[i] = (0, -1)
            inq[i] = True
            while len(queue) != 0:
                u = queue[0]
                for v, port in self.graph.go_from(u):
                    if dis[v][0] > dis[u][0] + 1:
                        dis[v] = (dis[u][0] + 1, port)
                        if not inq[v]:
                            queue.append(v)
                            inq[v] = True
                inq[u] = False
                del queue[0]

            for j in range(self.graph.n):
                v, port = dis[j]
                if v == 1e9:
                    continue
                if port == -1:
                    continue
                if i in self.res:
                    self.res[i][j] = port
                else:
                    self.res[i] = {}
                    self.res[i][j] = port
        print(self.res)

if __name__ = "__main__":
    