package eth

import (
	"context"
	"fmt"
	"hash"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rpc"

	txtrace "github.com/DeBankDeFi/etherlib/pkg/txtracev1"
	// "github.com/DeBankDeFi/eth/txtrace"
	"golang.org/x/crypto/sha3"
)

type helpHash struct {
	hashed hash.Hash
}

func newHash() *helpHash {

	return &helpHash{hashed: sha3.NewLegacyKeccak256()}
}

func (h *helpHash) Reset() {
	h.hashed.Reset()
}

func (h *helpHash) Update(key, val []byte) {
	h.hashed.Write(key)
	h.hashed.Write(val)
}

func (h *helpHash) Hash() common.Hash {
	return common.BytesToHash(h.hashed.Sum(nil))
}

type PreExecTx struct {
	ChainId                                     *big.Int
	From, To, Data, Value, Gas, GasPrice, Nonce string
}

type preData struct {
	block   *types.Block
	tx      *types.Transaction
	msg     types.Message
	stateDb *state.StateDB
	header  *types.Header
}

// PreExecAPI provides pre exec info for rpc
type PreExecAPI struct {
	e *Ethereum
}

func NewPreExecAPI(e *Ethereum) *PreExecAPI {
	return &PreExecAPI{e: e}
}

func (api *PreExecAPI) getBlockAndMsg(origin *PreExecTx, number *big.Int) (*types.Block, types.Message) {
	fromAddr := common.HexToAddress(origin.From)
	toAddr := common.HexToAddress(origin.To)

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    hexutil.MustDecodeUint64(origin.Nonce),
		To:       &toAddr,
		Value:    hexutil.MustDecodeBig(origin.Value),
		Gas:      hexutil.MustDecodeUint64(origin.Gas),
		GasPrice: hexutil.MustDecodeBig(origin.GasPrice),
		Data:     hexutil.MustDecode(origin.Data),
	})

	number.Add(number, big.NewInt(1))
	block := types.NewBlock(
		&types.Header{Number: number},
		[]*types.Transaction{tx}, nil, nil, newHash())

	msg := types.NewMessage(
		fromAddr,
		&toAddr,
		hexutil.MustDecodeUint64(origin.Nonce),
		hexutil.MustDecodeBig(origin.Value),
		hexutil.MustDecodeUint64(origin.Gas),
		hexutil.MustDecodeBig(origin.GasPrice),
		tx.GasFeeCap(),
		tx.GasTipCap(),
		hexutil.MustDecode(origin.Data),
		nil, false, true,
	)
	return block, msg
}

func (api *PreExecAPI) prepareData(ctx context.Context, origin *PreExecTx) (*preData, error) {
	var (
		d   preData
		err error
	)
	bc := api.e.blockchain
	d.header, err = api.e.APIBackend.HeaderByNumber(ctx, rpc.LatestBlockNumber)
	if err != nil {
		return nil, err
	}
	latestNumber := d.header.Number
	parent := api.e.blockchain.GetBlockByNumber(latestNumber.Uint64())
	d.stateDb, err = state.New(parent.Header().Root, bc.StateCache(), bc.Snapshots())
	if err != nil {
		return nil, err
	}
	d.block, d.msg = api.getBlockAndMsg(origin, latestNumber)
	d.tx = d.block.Transactions()[0]
	return &d, nil
}

func (api *PreExecAPI) GetLogs(ctx context.Context, origin *PreExecTx) (*types.Receipt, error) {
	var (
		bc = api.e.blockchain
	)
	d, err := api.prepareData(ctx, origin)
	if err != nil {
		return nil, err
	}
	gas := d.tx.Gas()
	gp := new(core.GasPool).AddGas(gas)

	d.stateDb.Prepare(d.tx.Hash(), 0)
	receipt, err := core.ApplyTransactionForPreExec(
		bc.Config(), bc, nil, gp, d.stateDb, d.header, d.tx, d.msg, &gas, *bc.GetVMConfig())
	if err != nil {
		return nil, err
	}
	return receipt, receipt.Err
}

// TraceTransaction tracing pre-exec transaction object.
func (api *PreExecAPI) TraceTransaction(ctx context.Context, origin *PreExecTx) (interface{}, error) {
	var (
		bc     = api.e.blockchain
		tracer *txtrace.OeTracer
		err    error
	)
	d, err := api.prepareData(ctx, origin)
	if err != nil {
		return nil, err
	}
	txContext := core.NewEVMTxContext(d.msg)
	txIndex := 0

	tracer = txtrace.NewOeTracer(nil)
	// Run the transaction with tracing enabled.
	vmenv := vm.NewEVM(core.NewEVMBlockContext(d.header, bc, nil), txContext, d.stateDb, bc.Config(), vm.Config{Debug: true, Tracer: tracer})
	vmenv.Context.BaseFee = big.NewInt(0)

	// Call Prepare to clear out the statedb access list
	d.stateDb.Prepare(d.tx.Hash(), txIndex)

	tracer.SetMessage(d.block.Number(), d.block.Hash(), d.tx.Hash(), uint(txIndex), d.msg.From(), d.msg.To(), *d.msg.Value())

	_, err = core.ApplyMessage(vmenv, d.msg, new(core.GasPool).AddGas(d.msg.Gas()))
	if err != nil {
		return nil, fmt.Errorf("tracing failed: %v", err)
	}

	tracer.Finalize()
	return tracer.GetResult(), nil
}
