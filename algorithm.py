#!/usr/bin/env python

# a sample tree node class
# - children are held in a list
# - children can be sorted
class anode():
    def __init__(self, item, children=None):
        self.item = item
        self.children = children
        if self.children == None:
            self.children = []
        self.root = False

    def apply_sort(self, sort_key=None):
        for c in self.children:
            c.apply_sort(sort_key)

        if sort_key:
            self.children = sorted(self.children, key=lambda n: sort_key(n.item))
        else:
            self.children = sorted(self.children, key=lambda n: n.item)

    def __str_depth__(self, depth):
        result = '  '*depth + str(self.item)
        if self.children:
            result += '\n'
            result += '\n'.join([c.__str_depth__(depth+1) for c in self.children])
        return result

    def __str__(self):
        return self.__str_depth__(0)

def build_worker(tree, item, relation):
    # if item<R>tree then item is placed above
    #
    #  tree         item
    #  / | \  -->     |  
    # A  B  C       tree
    #               / | \
    #              A  B  C
    #
    if not tree.root and relation(item, tree.item):
        return anode(item, [tree])

    # if item<R>child for any of tree's children, item is placed above those children:
    #
    #  tree          tree
    #  / | \  -->    /  \
    # A  B  C       A  item
    #                  /  \
    #                 B    C
    #
    if included := [n for n in tree.children if relation(item, n.item)]:
        discluded = [n for n in tree.children if not relation(item, n.item)]
        tree.children = discluded
        tree.children.append(anode(item, included))
        return tree

    # if child<R>item for any of tree's children, item is recursively placed below it
    #
    #  tree          tree
    #  / | \  -->    / | \
    # A  B  C       A  B  C
    #                     |
    #                   item
    #
    for i,node in enumerate(tree.children):
        if relation(node.item, item):
            tree.children[i] = build_worker(node, item, relation)
            return tree

    # otherwise, it's assumed tree.item<R>item and item is placed at current level
    #
    #  tree         tree
    #  / |   -->    / | \
    # A  B         A  B  item
    #                     
    assert tree.root or relation(tree.item, item)
    tree.children.append(anode(item))
    return tree

def build(items, relation, sort_func=None):
    root = anode("root")
    root.root = True

    for item in items:
        build_worker(root, item, relation)

    if sort_func:
        root.apply_sort(sort_func)

    return root
