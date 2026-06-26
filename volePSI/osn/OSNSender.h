#pragma once

#include <vector>
#include <map>
#include <string>
#include "volePSI/Defines.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "benes.h"

// © 2025 Digital Trust Centre - Nanyang Technological University. All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using namespace volePSI;
using namespace oc;

class OSNSender
{
	size_t size;
	int ot_type;
	oc::Timer *timer;
	std::vector<int> mPi;
	Benes benes;
	std::unique_ptr<osuCrypto::SilentOtExtReceiver> getSilentOtExtReceiver(osuCrypto::u64 numOTs);

	task<> silent_ot_recv(osuCrypto::BitVector &choices,
						  std::vector<osuCrypto::block> &recvMsg,
						  Socket &chl);
	task<> rand_ot_recv(osuCrypto::BitVector &choices,
						std::vector<osuCrypto::block> &recvMsg,
						Socket &chl);
	task<> gen_benes_server_osn(int values, Socket &chl, std::vector<std::array<osuCrypto::block, 2>> &recvMsg);

public:
	std::vector<int> dest;
	OSNSender(size_t size = 0, int ot_type = 0);
	void init(size_t size, int ot_type = 0, const std::string &osn_cache = "", const std::vector<uint64_t> intersection = {});
	void init_wj(size_t size, int ot_type, const std::string &osn_cache, std::map<int, int> &i2locptr);
	// Same as init_wj but seeds the Fisher-Yates PRNG explicitly. Required
	// for any multi-round shuffle protocol that needs different
	// permutations across rounds (init_wj uses a hardcoded seed, so all
	// invocations at the same size produce the same dest). Caller must
	// agree on the seed with the OSNReceiver counterpart out of band.
	void init_wj_seeded(size_t size, int ot_type, const std::string &osn_cache,
	                    std::map<int, int> &i2locptr, oc::block seed);
	std::vector<int> getmyPi(const std::map<int, int> &i2loc, const std::vector<u64> &intersection);
	std::vector<int> getPi() { return mPi; }
	void setPi(std::vector<int> myPi) { mPi = myPi; }
	task<> run_osn(Socket &chl, std::vector<oc::block> &input_vec);
	void setTimer(oc::Timer &timer);
	oc::Timer &getTimer() { return *timer; };
};
