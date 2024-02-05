package bpf

/*
#include <rte_bpf_ethdev.h>
*/
import "C"
import (
	"unsafe"

	"github.com/yerden/go-dpdk/common"
)

// LoadRX loads BPF program from the ELF file and install callback to execute it
// on given RX port/queue.
func LoadRX(port uint16, queue uint16, p *Prm, fname string, sname string, flags uint32) error {
	cfname := C.CString(fname)
	defer C.free(unsafe.Pointer(cfname))
	csname := C.CString(sname)
	defer C.free(unsafe.Pointer(csname))

	cp := p.transform()
	return common.IntErr(int64(
		C.rte_bpf_eth_rx_elf_load(C.uint16_t(port), C.uint16_t(queue), &cp, cfname, csname, C.uint32_t(flags))))
}

// UnloadRX unloads previously loaded BPF program (if any) from given RX
// port/queue and remove appropriate RX port/queue callback.
func UnloadRX(port uint16, queue uint16) {
	C.rte_bpf_eth_rx_unload(C.uint16_t(port), C.uint16_t(queue))
}

// LoadTX loads BPF program from the ELF file and install callback to execute it
// on given TX port/queue.
func LoadTX(port uint16, queue uint16, p *Prm, fname string, sname string, flags uint32) error {
	cfname := C.CString(fname)
	defer C.free(unsafe.Pointer(cfname))
	csname := C.CString(sname)
	defer C.free(unsafe.Pointer(csname))

	cp := p.transform()
	return common.IntErr(int64(
		C.rte_bpf_eth_tx_elf_load(C.uint16_t(port), C.uint16_t(queue), &cp, cfname, csname, C.uint32_t(flags))))
}

// UnloadTx unloads previously loaded BPF program (if any) from given TX
// port/queue and remove appropriate RX port/queue callback.
func UnloadTx(port uint16, queue uint16) {
	C.rte_bpf_eth_tx_unload(C.uint16_t(port), C.uint16_t(queue))
}
