// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <validationinterface.h>

namespace {

const TestingSetup* g_setup;
std::vector<COutPoint> g_outpoints_coinbase_init;

void initialize_tx_pool()
{
    static const auto testing_setup = MakeFuzzingContext<const TestingSetup>();
    g_setup = testing_setup.get();

    for (int i = 0; i < 2 * COINBASE_MATURITY; i++) {
        CTxIn in = MineBlock(g_setup->m_node, P2WSH_OP_TRUE);
        // Remember the txids to avoid expensive disk acess later on
        g_outpoints_coinbase_init.push_back(in.prevout);
    }
    SyncWithValidationInterfaceQueue();
}

struct TransactionsDelta final : public CValidationInterface {
    std::set<CTransactionRef>& m_removed;
    std::set<CTransactionRef>& m_added;

    explicit TransactionsDelta(std::set<CTransactionRef>& r, std::set<CTransactionRef>& a)
        : m_removed{r}, m_added{a} {}

    void TransactionAddedToMempool(const CTransactionRef& tx, uint64_t /* mempool_sequence */) override
    {
        Assert(m_added.insert(tx).second);
    }

    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t /* mempool_sequence */) override
    {
        Assert(m_removed.insert(tx).second);
    }
};

FUZZ_TARGET_INIT(tx_pool_standard, initialize_tx_pool)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const auto& node = g_setup->m_node;

    {
        const auto time_fuzzed = ConsumeTime(fuzzed_data_provider);
        SetMockTime(time_fuzzed);
    }
    // All spendable outpoints
    std::set<COutPoint> outpoints;
    for (const auto& outpoint : g_outpoints_coinbase_init) {
        Assert(outpoints.insert(outpoint).second);
        if (outpoints.size() >= COINBASE_MATURITY) break;
    }
    // The sum of the values of all spendable outpoints
    constexpr CAmount SUPPLY_TOTAL{COINBASE_MATURITY * 50 * COIN};

    CTxMemPool tx_pool;

    // Helper to query an amount
    const CCoinsViewMemPool amount_view{WITH_LOCK(::cs_main, return &node.chainman->ActiveChainstate().CoinsTip()), tx_pool};
    const auto GetAmount = [&](const COutPoint& outpoint) {
        Coin c;
        amount_view.GetCoin(outpoint, c);
        Assert(!c.IsSpent());
        return c.out.nValue;
    };

    while (fuzzed_data_provider.ConsumeBool()) {
        {
            // Total supply is the mempool fee + all spendable outpoints
            CAmount supply_now{WITH_LOCK(tx_pool.cs, return tx_pool.GetTotalFee())};
            for (const auto& op : outpoints) {
                supply_now += GetAmount(op);
            }
            Assert(supply_now == SUPPLY_TOTAL);
        }
        if (fuzzed_data_provider.ConsumeBool()) {
            const auto time_fuzzed = ConsumeTime(fuzzed_data_provider);
            SetMockTime(time_fuzzed);
        }
        if (fuzzed_data_provider.ConsumeBool()) {
            node.args->ForceSetArg("-limitancestorcount",
                                   ToString(fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 200)));
            node.args->ForceSetArg("-limitancestorsize",
                                   ToString(fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 200)));
            node.args->ForceSetArg("-limitdescendantcount",
                                   ToString(fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 200)));
            node.args->ForceSetArg("-limitdescendantsize",
                                   ToString(fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 200)));
            node.args->ForceSetArg("-maxmempool",
                                   ToString(fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 200)));
            node.args->ForceSetArg("-mempoolexpiry",
                                   ToString(fuzzed_data_provider.ConsumeIntegralInRange<unsigned>(0, 200)));
        }
        if (outpoints.empty()) return;

        // Create transaction to add to the mempool
        const CTransactionRef tx = [&] {
            CMutableTransaction tx_mut;
            tx_mut.nVersion = CTransaction::CURRENT_VERSION;
            tx_mut.nLockTime = fuzzed_data_provider.ConsumeBool() ? 0 : fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            const auto num_in = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, outpoints.size());
            const auto num_out = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, outpoints.size());

            CAmount amount_in{0};
            for (int i = 0; i < num_in; ++i) {
                // Pop random outpoint
                auto pop = outpoints.begin();
                std::advance(pop, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, outpoints.size() - 1));
                const auto outpoint = *pop;
                outpoints.erase(pop);
                amount_in += GetAmount(outpoint);

                // Create input
                const auto sequence = fuzzed_data_provider.ConsumeBool() ?
                                          fuzzed_data_provider.PickValueInArray({CTxIn::SEQUENCE_FINAL, CTxIn::SEQUENCE_FINAL - 1}) :
                                          fuzzed_data_provider.ConsumeIntegral<uint32_t>();
                const auto script_sig = CScript{};
                const auto script_wit_stack = std::vector<std::vector<uint8_t>>{WITNESS_STACK_ELEM_OP_TRUE};
                CTxIn in;
                in.prevout = outpoint;
                in.nSequence = sequence;
                in.scriptSig = script_sig;
                in.scriptWitness.stack = script_wit_stack;

                tx_mut.vin.push_back(in);
            }
            const CAmount max_amount_out{amount_in / num_out};
            for (int i = 0; i < num_out; ++i) {
                const auto amount_out = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(0, max_amount_out);
                tx_mut.vout.emplace_back(amount_out, P2WSH_OP_TRUE);
            }
            const auto tx = MakeTransactionRef(tx_mut);
            // Restore previously removed outpoints
            for (const auto& in : tx->vin) {
                Assert(outpoints.insert(in.prevout).second);
            }
            return tx;
        }();

        // Remember all removed and added transaction
        std::set<CTransactionRef> removed;
        std::set<CTransactionRef> added;
        auto txr = std::make_shared<TransactionsDelta>(removed, added);
        RegisterSharedValidationInterface(txr);
        const bool bypass_limits = fuzzed_data_provider.ConsumeBool();
        const bool require_standard = fuzzed_data_provider.ConsumeBool();
        ::fRequireStandard = require_standard;
        const auto res = WITH_LOCK(::cs_main, return AcceptToMemoryPool(tx_pool, tx, bypass_limits));
        const bool accepted = res.m_result_type == MempoolAcceptResult::ResultType::VALID;
        SyncWithValidationInterfaceQueue();
        UnregisterSharedValidationInterface(txr);

        Assert(accepted != added.empty());
        Assert(accepted == res.m_state.IsValid());
        Assert(accepted != res.m_state.IsInvalid());
        if (accepted) {
            Assert(added.size() == 1); // For now, no package acceptance
            Assert(tx == *added.begin());
        }

        // Do not consider rejected transaction removed
        removed.erase(tx);

        // Helper to insert spent and created outpoints of a tx into collections
        const auto insert_tx = [](auto& tx_outs, auto& tx_ins, const auto& tx) {
            for (size_t i{0}; i < tx->vout.size(); ++i) {
                Assert(tx_outs.emplace(tx->GetHash(), i).second);
            }
            for (const auto& in : tx->vin) {
                Assert(tx_ins.insert(in.prevout).second);
            }
        };
        // Add created outpoints, remove spent outpoints
        {
            std::set<COutPoint> pop;
            for (const auto& r : removed) {
                insert_tx(/* tx_outs */ pop, /* tx_ins */ outpoints, /* tx */ r);
            }
            for (const auto& a : added) {
                insert_tx(/* tx_outs */ outpoints, /* tx_ins */ pop, /* tx */ a);
            }
            for (const auto& p : pop) {
                Assert(outpoints.erase(p) == 1);
            }
        }
    }
    SyncWithValidationInterfaceQueue();
}

FUZZ_TARGET_INIT(tx_pool, initialize_tx_pool)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    std::vector<uint256> txids;
    for (const auto& outpoint : g_outpoints_coinbase_init) {
        txids.push_back(outpoint.hash);
    }
    CTxMemPool tx_pool;

    while (fuzzed_data_provider.ConsumeBool()) {
        const auto mut_tx = ConsumeTransaction(fuzzed_data_provider, txids);

        const auto tx = MakeTransactionRef(mut_tx);
        const bool bypass_limits = fuzzed_data_provider.ConsumeBool();
        const bool require_standard = fuzzed_data_provider.ConsumeBool();
        ::fRequireStandard = require_standard;
        const auto res = WITH_LOCK(::cs_main, return AcceptToMemoryPool(tx_pool, tx, bypass_limits));
        const bool accepted = res.m_result_type == MempoolAcceptResult::ResultType::VALID;
        if (accepted) {
            txids.push_back(tx->GetHash());
        }

        SyncWithValidationInterfaceQueue();
    }
}
} // namespace
