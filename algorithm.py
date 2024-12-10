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

def build(items, relation):
    root = anode("root")
    root.root = True

    for item in items:
        build_worker(root, item, relation)

    return root

if __name__ == '__main__':
    # "is prefix of" relation
    stuff = {'a', 'aardvark', 'ant', 'anteater', 'antelope'}
    tree = build(stuff, lambda a,b: b.startswith(a))
    print(tree)

    # same
    stuff = {'sve_int_brkp', 'sve_int_cmp_0', 'sve_int_cmp_1', 'sve_int_count',
                'sve_int_count_r', 'sve_int_count_r_sat', 'sve_int_count_v',
                'sve_int_count_v_sat', 'sve_int_countvlv0', 'sve_int_countvlv1',
                'sve_int_cterm', 'sve_int_dup_fpimm', 'sve_int_dup_fpimm_pred',
                'sve_int_dup_imm', 'sve_int_dup_imm_pred'}
    tree = build(stuff, lambda a,b: b.startswith(a))
    print(tree)

    # same
    stuff = {'./lib/.DS_Store', './lib/clang/11.0.0/include/rtmintrin.h',
        './lib/clang/11.0.0/include/waitpkgintrin.h', './lib/clang/11.0.0/lib',
        './lib/clang/11.0.0/lib/wasi', './lib/clang/11.0.0/lib/wasi/libclang_rt.builtins-wasm32.a',
        './share', './share/clang', './share/clang/clang-format-bbedit.applescript',
        './share/clang/clang-format-diff.py'}
    tree = build(stuff, lambda a,b: b.startswith(a))
    print(tree)

    # "is superset of" relation
    stuff = [{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, {3, 4, 5, 6, 7}, {6, 7}, {4, 5, 6},
            {4, 5}, {5}, {8, 9, 10, 7}, {8}, {9, 10}, {1, 2}]
    tree = build(stuff, lambda a,b: a.issuperset(b))
    print(tree)

    # "divides" relation
    stuff = list(range(10))
    tree = build(stuff, lambda a,b: b%a==0)
    print(tree)
