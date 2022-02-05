#include "sha_table.cuh"

#define HASHOP_ADD 0
#define HASHOP_XOR 1
#define HASHOP_SHA_SINGLE 2
#define HASHOP_SHA_LOOP 3
#define HASHOP_MEMGEN 4
#define HASHOP_MEMADD 5
#define HASHOP_MEMXOR 6
#define HASHOP_MEM_SELECT 7
#define HASHOP_END 8
#define HASHOP_READMEM2 9
#define HASHOP_LOOP 10
#define HASHOP_ENDLOOP 11
#define HASHOP_IF 12
#define HASHOP_STORETEMP 13
#define HASHOP_EXECOP 14
#define HASHOP_MEMADDHASHPREV 15
#define HASHOP_MEMXORHASHPREV 16

__kernel void dyn_hash (__global uint* byteCode, __global uint* hashResult, __global uint* hostHeader, __global uint* NonceRetBuf, const ulong target, __global uint* global_memgen) {
	
	int computeUnitID = get_global_id(0) - get_global_offset(0);

	__global uint* hostHashResult = &hashResult[computeUnitID * 8];

	uint myHeader[20];
	uint myHashResult[8];

	uint nonce = get_global_id(0) * GPU_LOOPS;

	for ( int i = 0; i < 19; i++)
		myHeader[i] = hostHeader[i];
	
	myHeader[19] = nonce;
	
	uint bestNonce = nonce;
	uint bestDiff = 0;
	uint bestHash[8];

	uint prevHashSHA[8];
	sha256(32, &myHeader[1], prevHashSHA);

	__global uint* myMemGen = &global_memgen[computeUnitID * 512 * 8];
	uint tempStore[8];
	
	uint hashCount = 0;
	while (hashCount < GPU_LOOPS)
	{
		sha256(80, myHeader, myHashResult);

		uint linePtr = 0;
		uint done = 0;
		uint currentMemSize = 0;
		uint instruction = 0;

		uint loop_opcode_count;
		uint loop_line_ptr;

		while (1)
		{
			auto hashop = byteCode[linePtr++];

			// TODO divergent branching, we must run this code on the entire warp!
			// However, SHA256 cannot be parallelized for 32 threads
			if (hashop == HASHOP_ADD)
			{
				for (int i = 0; i < 8; i++)
					myHashResult[i] += byteCode[linePtr + i];
				linePtr += 8;
			}
			else if (hashop == HASHOP_XOR)
			{
				for (int i = 0; i < 8; i++)
					myHashResult[i] ^= byteCode[linePtr + i];
				linePtr += 8;
			}
			else if (hashop == HASHOP_SHA_SINGLE)
			{
				sha256(32, myHashResult, myHashResult);
			}
			else if (hashop == HASHOP_SHA_LOOP)
			{
				uint loopCount = byteCode[linePtr];
				for (int i = 0; i < loopCount; i++)
					sha256(32, myHashResult, myHashResult);
				linePtr++;
			}
			else if (hashop == HASHOP_MEMGEN)
			{
				currentMemSize = byteCode[linePtr];

				for (int i = 0; i < currentMemSize; i++)
				{
					sha256(32, myHashResult, myHashResult);
					for (int j = 0; j < 8; j++)
						myMemGen[i*8+j] = myHashResult[j];
				}

				linePtr++;
			}
			else if (hashop == HASHOP_MEMADD)
			{
				for (int i = 0; i < currentMemSize; i++)
					for (int j = 0; j < 8; j++)
						myMemGen[i*8+j] += byteCode[linePtr + j];

				linePtr += 8;
			}
			else if (hashop == HASHOP_MEMADDHASHPREV)
			{
				for (int i = 0; i < currentMemSize; i++)
					for (int j = 0; j < 8; j++) {
						myMemGen[i * 8 + j] += myHashResult[j] + prevHashSHA[j];
					}
			}
			else if (hashop == HASHOP_MEMXOR)
			{
				for (int i = 0; i < currentMemSize; i++)
					for (int j = 0; j < 8; j++)
						myMemGen[i * 8 + j] ^= byteCode[linePtr + j];

				linePtr += 8;
			}
			else if (hashop == HASHOP_MEMXORHASHPREV)
			{
				for (int i = 0; i < currentMemSize; i++)
					for (int j = 0; j < 8; j++)
					{
						myMemGen[i * 8 + j] += myHashResult[j];
						myMemGen[i * 8 + j] ^= prevHashSHA[j];
					}
			}
			else if (hashop == HASHOP_MEM_SELECT)
			{
				uint index = byteCode[linePtr] % currentMemSize;
				for (int j = 0; j < 8; j++)
					myHashResult[j] = myMemGen[index*8 + j];

				linePtr++;
			}
			else if (hashop == HASHOP_READMEM2)
			{
				if (byteCode[linePtr] == 0)
				{
					for (int i = 0; i < 8; i++)
						myHashResult[i] ^= prevHashSHA[i];
				}
				else if (byteCode[linePtr] == 1)
				{
					for (int i = 0; i < 8; i++)
						myHashResult[i] += prevHashSHA[i];
				}

				linePtr++;  //this is the source, only supports prev hash currently

				uint index = 0;
				for (int i = 0; i < 8; i++)
					index += myHashResult[i];

				index = index % currentMemSize;

				for (int j = 0; j < 8; j++)
					myHashResult[j] = myMemGen[index*8+j];

				linePtr++;
			}
			else if (hashop == HASHOP_LOOP)
			{
				loop_opcode_count = 0;
				for (int j = 0; j < 8; j++)
					loop_opcode_count += myHashResult[j];

				loop_opcode_count = loop_opcode_count % byteCode[linePtr] + 1;

				linePtr++;
				loop_line_ptr = linePtr;		//line to return to after endloop
			}
			else if (hashop == HASHOP_ENDLOOP)
			{
				loop_opcode_count--;
				if (loop_opcode_count > 0)
					linePtr = loop_line_ptr;
			}
			else if (hashop == HASHOP_IF)
			{
				uint sum = 0;
				for (int j = 0; j < 8; j++)
					sum += myHashResult[j];
				sum = sum % byteCode[linePtr];
				linePtr++;
				uint numToSkip = byteCode[linePtr];
				linePtr++;
				if (sum == 0)
					linePtr += numToSkip;
			}
			else if (hashop == HASHOP_STORETEMP)
			{
				for (int j = 0; j < 8; j++)
					tempStore[j] = myHashResult[j];
			}
			else if (hashop == HASHOP_EXECOP)
			{
				//next byte is source  (hard coded to temp)
				linePtr++;

				uint sum = 0;
				for (int j = 0; j < 8; j++)
					sum += myHashResult[j];

				if (sum % 3 == 0)
				{
					for (int i = 0; i < 8; i++)
						myHashResult[i] += tempStore[i];
				}
				else if (sum % 3 == 1)
				{
					for (int i = 0; i < 8; i++)
						myHashResult[i] ^= tempStore[i];
				}
				else if (sum % 3 == 2) {
					sha256(32, myHashResult, myHashResult);
				}
			}
			else if (hashop == HASHOP_END)
				break;
		}
		
		ulong res = as_ulong(as_uchar8(((ulong *)myHashResult)[0]).s76543210);
		if(res <= target)
		{
			NonceRetBuf[atomic_inc(NonceRetBuf + 0xFF)] = nonce;
			break;	// we are solo mining, any other solutions will go to waste anyhow
		}
		
		hashCount++;
		nonce++;
		myHeader[19] = nonce;
	}
}

