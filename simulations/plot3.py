#!/usr/bin/env python3.7

"""Script to visualize the results."""


import csv
import pathlib

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import seaborn as sns


HERE = pathlib.Path(__file__).resolve().parent

METRICS = [
    ('round_wall_sum', 'time until signature (sec)', 'protocol duration', 1, False),
    ('bandwidth_msg_tx_sum', 'messages sent per active node', 'message count', 1, True),
    ('bandwidth_tx_sum', 'data sent per active node (kB)', 'data transferred', 0.001, True),
]

PALETTE = sns.color_palette('hls', 3)
PALETTE[:2], PALETTE[2:] = PALETTE[1:], PALETTE[:1]


def analysis_1():
    ref = parse('simulations_blscosibundle', can_differ=['hosts', 'failingleaves'])
    new = parse('simulations_mask_simple', can_differ=['hosts', 'failingleaves'])
    new2 = parse('simulations_mask_aggr', can_differ=['hosts', 'failingleaves'])

    assert (ref.hosts == new.hosts).all()
    assert (ref.failingleaves == new.failingleaves).all()
    assert (ref.mindelay == new.mindelay).all()
    assert (ref.maxdelay == new.maxdelay).all()
    assert (ref.rounds == 1).all()
    assert (new.rounds == 1).all()
    assert (new2.rounds == 1).all()

    sizes = ref.hosts.unique()

    palette = sns.color_palette(n_colors=3)
    for num_nodes in sizes:
        ref_part = ref[ref.hosts == num_nodes]
        new_part = new[new.hosts == num_nodes]
        new2_part = new2[new2.hosts == num_nodes]
        ref_failure = ref_part.round_wall_avg.isnull()
        new_failure = new_part.round_wall_avg.isnull()
        new2_failure = new2_part.round_wall_avg.isnull()


        for metric, label, title, factor, per_node in METRICS:

            # fig, ax = plt.subplots()
            # fig.set_size_inches(11.7, 8.27)
            # Workaround for legend colors
#             sns.stripplot(ref_part.failingleaves, ref_part[metric], size=5, palette=palette)
#             handles, _, _, _ = matplotlib.legend._parse_legend_args([ax], ['', '', ''])
#             ax.clear()
#             ax.legend(handles, ['Existing Gossip Aggregation', 'Mask', 'Mask Aggregation'])

            if per_node:
                num_working = ref_part.hosts - ref_part.failingleaves
                factor_adj = factor / num_working
            else:
                factor_adj = factor
            y_ref = extract_dataframe(ref_part, metric, factor, per_node)
            y_new = extract_dataframe(new_part, metric, factor, per_node)
            y_new2 = extract_dataframe(new2_part, metric, factor, per_node)
#             sns.catplot(ref_part.failingleaves, y_ref, color=palette[0])
#             sns.catplot(new_part.failingleaves, y_new,  color=palette[1])
            y_ref["Protocol"] = "BLS CoSi"
            y_new["Protocol"] = "Mask"
            y_new2["Protocol"] = "Mask Aggregation"
            final = pd.concat([y_ref, y_new, y_new2])
            # sns.set(rc={'figure.figsize':(12,6)})
            splot = sns.catplot(x="failingleaves", y=metric,data=final, kind="box", hue="Protocol", legend_out=False)
            plt.gcf().set_size_inches(7.36, 5.52)
            plt.title(f'Comparison of {title} ($n={num_nodes}$)')
            plt.xlabel('failing nodes')
            plt.ylabel(label)
            ax = splot.axes[0][0]
            handles, labels = ax.get_legend_handles_labels()
            ax.legend(handles=handles, labels=labels)
            # plt.legend(loc="upper left", labels= ['Existing Gossip Aggregation', 'Mask', 'Mask Aggregation'])
            save_fig(f'aggregation_{metric}_{num_nodes}', 1)

def sanity_checks(results, can_differ=(), treemode=None, check_failures=True):
    attributes = {'rounds', 'hosts', 'failingleaves', 'maxdelay', 'mindelay',
                  'gossiptick', 'rumorpeers', 'shutdownpeers'}

    if 'delay' in can_differ:
        check = attributes.remove('maxdelay')
        check = attributes.remove('mindelay')
    check = attributes.difference(can_differ)

    assert not results.empty

    for attribute in check:
        assert (results[attribute] == results[attribute][0]).all(), attribute

    if treemode is not None:
        assert (results.treemode == treemode).all()

    if check_failures:
        assert not results.round_wall_avg.isnull().any()
        assert (results.round_wall_sum != 0).all()
        assert (results.bandwidth_msg_tx_sum != 0).all()
        assert (results.bandwidth_tx_sum != 0).all()


def parse(name, check_sanity=True, **sanity_kwargs):
    path = HERE / 'test_data' / (name + '.csv')
    results = pd.read_csv(path)
    if check_sanity:
        sanity_checks(results, **sanity_kwargs)
    return results

def extract(results, metric, factor, per_node):
    num_rounds = next(iter(results.rounds))
    if per_node:
        num_working = results.hosts - results.failingleaves
        factor /= num_working
    return results[metric] * factor / num_rounds

def extract_dataframe(results, metric, factor, per_node):
    num_rounds = next(iter(results.rounds))
    if per_node:
        num_working = results.hosts - results.failingleaves
        factor /= num_working
    results = results.assign(metric = results[metric] * factor / num_rounds)
    return results

def save_fig(name, analysis, tight_layout=True, ylim=(0, None), close=True):
    path = HERE / 'figures' / str(analysis) / (name + '.png')
    plt.ylim(ylim)
    if tight_layout:
        plt.tight_layout()
    plt.savefig(path)
    if close:
        plt.close()


def main():
    matplotlib.rcParams['figure.figsize'] = 7.36, 5.52
    sns.set_style('whitegrid')
    sns.set_context('notebook')
    analysis_1()


if __name__ == '__main__':
    main()
