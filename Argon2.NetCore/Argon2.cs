/*
 * Based on original found here:
 * https://github.com/mheyman/Isopoh.Cryptography.Argon2/
 * Modified for usage with pinnedmemory over securearray
 * also modified to fit bouncy castle code structure and updated C#
 * despite changes all credit for work should be retained by
 * the original author.
 */

using System;
using System.Buffers.Binary;
using System.Linq;
using System.Runtime.InteropServices;
using System.Numerics;
using System.Threading;
using PinnedMemory;

namespace Argon2.NetCore
{
    public class Argon2 : IDisposable
    {
        public enum AddressType
        {
            DependentAddressing = 0, // Argon2d
            IndependentAddressing = 1 // Argon2i
        }

        private const int _version = 0x13;
        private const int _blockSize = 1024;
        private const int _qwordsInBlock = _blockSize / 8;
        private const int _prehashDigestLength = 64;
        private const int _prehashSeedLength = 72;
        private const int _syncPoints = 4;

        private int _hashLength = 32;
        private int _memoryCost = 65536;
        private int _lanes = 4;
        private int _threads = 1;
        private int _timeCost = 3;
        private const int _minimumHashLength = 4;
        private readonly byte[] _salt;
        private byte[] _buffer;
        private readonly PinnedMemory<byte> _associatedDataPin;
        private readonly byte[] _associatedData;
        private readonly PinnedMemory<byte> _key;
        private PinnedMemory<ulong> _memory;
        private Blocks _memoryBlocks;
        private int _memoryBlockCount;
        private int _segmentLength;
        private int _laneLength;

        public AddressType Addressing { get; set; } = AddressType.IndependentAddressing;

        public int HashLength
        {
            set => _hashLength = value;
        }

        public int Lanes
        {
            get => _lanes;
            set => _lanes = value;
        }

        public int Threads
        {
            get => _threads;
            set => _threads = value;
        }

        public int MemoryCost
        {
            get => _memoryCost;
            set => _memoryCost = value;
        }

        public int TimeCost
        {
            get => _timeCost;
            set => _timeCost = value;
        }

        public int GetLength()
        {
            return _hashLength;
        }

        public Argon2(PinnedMemory<byte> key, byte[] salt, byte[] associatedData = null)
        {
            _salt = salt ?? throw new NullReferenceException("Salt can't be null.");
            _key = key ?? throw new NullReferenceException("Key can't be null.");
            _associatedData = associatedData;
            if (_associatedData != null)
                _associatedDataPin = new PinnedMemory<byte>(_associatedData, false);

            if (_salt.Length < 8)
                throw new ArgumentException("Salt must be 8 bytes or more.");

            ValidateParameters();
            ConfigureMemory();
        }

        public void Update(byte value)
        {
            var block = new byte[1];
            block[0] = value;
            _buffer = _buffer == null ? block : Append(_buffer, block);
        }

        public void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
        {
            UpdateBlock(value.ToArray(), offset, length);
            value.Dispose();
        }

        public void UpdateBlock(byte[] value, int offset, int length)
        {
            var block = new byte[length];
            Array.Copy(value, offset, block, 0, length);
            _buffer = _buffer == null ? block : Append(_buffer, block);
        }

        public void DoFinal(PinnedMemory<byte> output, int offset)
        {
            if (output == null)
                throw new ArgumentNullException(nameof(output));

            ValidateParameters();

            if (offset < 0 || offset > output.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset must be within the output buffer.");

            if (output.Length - offset < _hashLength)
                throw new ArgumentException("Output buffer is too small for the configured hash length.", nameof(output));

            ConfigureMemory();
            Initialize();
            FillMemoryBlocks();

            using var blockhashBuffer = new PinnedMemory<ulong>(new ulong[_blockSize / 8]);
            var blockhash = new Block(blockhashBuffer.ToArray(), 0);
            blockhash.Copy(_memoryBlocks[_laneLength - 1]);

            for (var l = 1; l < _lanes; ++l)
            {
                blockhash.Xor(_memoryBlocks[(l * _laneLength) + (_laneLength - 1)]);
            }

            using var blockhashBytes = new PinnedMemory<byte>(new byte[_blockSize]);
            StoreBlock(blockhashBytes.ToArray(), blockhash);
            using var outputBytes = new PinnedMemory<byte>(new byte[_hashLength]);
            Blake2BLong(outputBytes.ToArray(), blockhashBytes.ToArray());
            Array.Copy(outputBytes.ToArray(), 0, output.ToArray(), offset, _hashLength);

            ClearBuffer();
        }

        private void ClearBuffer()
        {
            if (_buffer == null)
                return;

            Array.Clear(_buffer, 0, _buffer.Length);
            _buffer = null;
        }

        private void ValidateParameters()
        {
            if (_lanes <= 0)
                throw new ArgumentOutOfRangeException(nameof(Lanes), "Lanes must be greater than zero.");

            if (_threads <= 0)
                throw new ArgumentOutOfRangeException(nameof(Threads), "Threads must be greater than zero.");

            if (_timeCost <= 0)
                throw new ArgumentOutOfRangeException(nameof(TimeCost), "TimeCost must be greater than zero.");

            if (_hashLength < _minimumHashLength)
                throw new ArgumentOutOfRangeException(nameof(HashLength), "HashLength must be at least 4 bytes.");

            if (_memoryCost <= 0)
                throw new ArgumentOutOfRangeException(nameof(MemoryCost), "MemoryCost must be greater than zero.");
        }

        private void ConfigureMemory()
        {
            _memory?.Dispose();

            var memoryBlocks = (uint)_memoryCost;
            if (memoryBlocks < 2 * _syncPoints * _lanes)
            {
                memoryBlocks = 2 * _syncPoints * (uint)_lanes;
            }

            _segmentLength = (int)(memoryBlocks / (_lanes * _syncPoints));
            _laneLength = _segmentLength * _syncPoints;
            _memoryBlockCount = _laneLength * _lanes;
            _memory = new PinnedMemory<ulong>(new ulong[_blockSize * _memoryBlockCount / 8]);
            _memoryBlocks = new Blocks(_memory.ToArray(), _memoryBlockCount);
        }

        private void Initialize()
        {
            using var hash = new PinnedMemory<byte>(new byte[_prehashSeedLength]);
            using (var init = InitialHash())
                Array.Copy(init.ToArray(), hash.ToArray(), _prehashDigestLength);

            FillFirstBlocks(hash.ToArray());
        }

        private PinnedMemory<byte> InitialHash()
        {
            var output = new PinnedMemory<byte>(new byte[64]);
            using var hash = new Blake2b.NetCore.Blake2b();
            var value = new byte[4];
            Store32(value, _lanes);
            hash.UpdateBlock(value, 0, 4);
            Store32(value, _hashLength);
            hash.UpdateBlock(value, 0, 4);
            Store32(value, _memoryCost);
            hash.UpdateBlock(value, 0, 4);
            Store32(value, _timeCost);
            hash.UpdateBlock(value, 0, 4);
            Store32(value, (uint)_version);
            hash.UpdateBlock(value, 0, 4);
            Store32(value, (uint)Addressing);
            hash.UpdateBlock(value, 0, 4);

            Store32(value, _buffer?.Length ?? 0);
            hash.UpdateBlock(value, 0, 4);
            if (_buffer != null)
                hash.UpdateBlock(_buffer, 0, _buffer.Length);

            Store32(value, _salt?.Length ?? 0);
            hash.UpdateBlock(value, 0, 4);
            if (_salt != null)
                hash.UpdateBlock(_salt, 0, _salt.Length);

            Store32(value, _key?.Length ?? 0);
            hash.UpdateBlock(value, 0, 4);
            if (_key != null)
                hash.UpdateBlock(_key.ToArray(), 0, _key.Length);

            Store32(value, _associatedData?.Length ?? 0);
            hash.UpdateBlock(value, 0, 4);
            if (_associatedData != null)
                hash.UpdateBlock(_associatedData, 0, _associatedData.Length);

            hash.DoFinal(output, 0);
            hash.Reset();

            return output;
        }

        private T[] Append<T>(T[] source, T[] destination, int sourceLength = 0, int destinationLength = 0)
        {
            var expandSourceLength = sourceLength > 0 ? sourceLength : source.Length;
            var expandDestinationLength = destinationLength > 0 ? destinationLength : destination.Length;
            var expanded = new T[expandSourceLength + expandDestinationLength];

            Array.Copy(source, 0, expanded, 0, expandSourceLength);
            Array.Copy(destination, 0, expanded, expandSourceLength, expandDestinationLength);

            return expanded;
        }

        private void FillFirstBlocks(byte[] blockhash)
        {
            using var blockhashBytes = new PinnedMemory<byte>(new byte[_blockSize]);
            for (var l = 0; l < _lanes; ++l)
            {
                Store32(blockhash, _prehashDigestLength, 0);
                Store32(blockhash, _prehashDigestLength + 4, l);
                Blake2BLong(blockhashBytes.ToArray(), blockhash);
                LoadBlock(_memoryBlocks[l * _laneLength], blockhashBytes.ToArray());
                Store32(blockhash, _prehashDigestLength, 1);
                Blake2BLong(blockhashBytes.ToArray(), blockhash);
                LoadBlock(_memoryBlocks[(l * _laneLength) + 1], blockhashBytes.ToArray());
            }
        }

        private void FillMemoryBlocks()
        {
            if (_threads > 1)
            {
                var waitHandles =
                    Enumerable.Range(
                        0,
                        _threads > _lanes ? _lanes : _threads)
                        .Select(i => new AutoResetEvent(false))
                        .Cast<WaitHandle>()
                        .ToArray();
                var threads = new Thread[waitHandles.Length];
                for (var passNumber = 0; passNumber < _timeCost; ++passNumber)
                {
                    for (var sliceNumber = 0; sliceNumber < _syncPoints; ++sliceNumber)
                    {
                        var laneNumber = 0;
                        var remaining = _lanes;
                        for (; laneNumber < threads.Length && laneNumber < _lanes; ++laneNumber)
                        {
                            threads[laneNumber] = StartFillSegmentThread(
                                passNumber,
                                laneNumber,
                                sliceNumber,
                                (AutoResetEvent)waitHandles[laneNumber]);
                        }

                        while (laneNumber < _lanes)
                        {
                            var i = WaitHandle.WaitAny(waitHandles);
                            threads[i].Join();
                            --remaining;
                            threads[i] = StartFillSegmentThread(
                                passNumber,
                                laneNumber,
                                sliceNumber,
                                (AutoResetEvent)waitHandles[i]);
                            ++laneNumber;
                        }

                        while (remaining > 0)
                        {
                            var i = WaitHandle.WaitAny(waitHandles);
                            threads[i].Join();
                            --remaining;
                        }
                    }
                }
            }
            else
            {
                for (var passNumber = 0; passNumber < _timeCost; ++passNumber)
                {
                    for (var sliceNumber = 0; sliceNumber < _syncPoints; ++sliceNumber)
                    {
                        for (var laneNumber = 0; laneNumber < _lanes; ++laneNumber)
                        {
                            FillSegment(
                                new Position
                                {
                                    Pass = passNumber,
                                    Lane = laneNumber,
                                    Slice = sliceNumber,
                                    Index = 0
                                });
                        }
                    }
                }
            }
        }

        private Thread StartFillSegmentThread(int pass, int lane, int slice, AutoResetEvent are)
        {
            var ret = new Thread(() =>
            {
                FillSegment(
                    new Position
                    {
                        Pass = pass,
                        Lane = lane,
                        Slice = slice,
                        Index = 0
                    });
                are.Set();
            });
            ret.Start();
            return ret;
        }

        private void FillSegment(Position position)
        {
            var dataIndependentAddressing = Addressing == AddressType.IndependentAddressing;
            var pseudoRands = new ulong[_segmentLength];
            if (dataIndependentAddressing)
                GenerateAddresses(position, pseudoRands);

            var startingIndex = position.Pass == 0 && position.Slice == 0 ? 2 : 0;
            var curOffset = (position.Lane * _laneLength) + (position.Slice * _segmentLength) + startingIndex;
            var prevOffset = curOffset % _laneLength == 0 ? curOffset + _laneLength - 1 : curOffset - 1;

            for (var i = startingIndex; i < _segmentLength; ++i, ++curOffset, ++prevOffset)
            {
                if (curOffset % _laneLength == 1)
                    prevOffset = curOffset - 1;

                var pseudoRand = dataIndependentAddressing ? pseudoRands[i] : _memoryBlocks[prevOffset][0];
                var refLane =
                    (position.Pass == 0 && position.Slice == 0)
                    ? position.Lane
                    : (int)((uint)(pseudoRand >> 32) % (uint)_lanes);

                position.Index = i;
                var refIndex = IndexAlpha(position, (uint)pseudoRand, refLane == position.Lane);

                var refBlock = _memoryBlocks[(_laneLength * refLane) + refIndex];
                var curBlock = _memoryBlocks[curOffset];
                if (position.Pass == 0)
                {
                    FillBlock(_memoryBlocks[prevOffset], refBlock, curBlock);
                }
                else
                {
                    FillBlockWithXor(_memoryBlocks[prevOffset], refBlock, curBlock);
                }
            }
        }

        private int IndexAlpha(Position position, uint pseudoRand, bool sameLane)
        {
            int referenceAreaSize;
            if (position.Pass == 0)
            {
                if (position.Slice == 0)
                {
                    referenceAreaSize = position.Index - 1;
                }
                else
                {
                    if (sameLane)
                    {
                        referenceAreaSize = (position.Slice * _segmentLength) + position.Index - 1;
                    }
                    else
                    {
                        referenceAreaSize = (position.Slice * _segmentLength) + (position.Index == 0 ? -1 : 0);
                    }
                }
            }
            else
            {
                if (sameLane)
                {
                    referenceAreaSize = _laneLength - _segmentLength + position.Index - 1;
                }
                else
                {
                    referenceAreaSize = _laneLength - _segmentLength + (position.Index == 0 ? -1 : 0);
                }
            }

            ulong relativePosition = pseudoRand;
            relativePosition = (relativePosition * relativePosition) >> 32;
            relativePosition = (uint)referenceAreaSize - 1 - (((uint)referenceAreaSize * relativePosition) >> 32);

            var startPosition = position.Pass != 0
                                    ? position.Slice == (_syncPoints - 1)
                                          ? 0
                                          : (position.Slice + 1) * _segmentLength
                                    : 0;
            var absolutePosition = (int)(((ulong)startPosition + relativePosition) % (ulong)_laneLength);
            return absolutePosition;
        }

        private void GenerateAddresses(Position position, ulong[] pseudoRands)
        {
            var buf = new ulong[_qwordsInBlock * 4];
            var zeroBlock = new Block(buf, 0);
            var inputBlock = new Block(buf, 1);
            var addressBlock = new Block(buf, 2);
            var tmpBlock = new Block(buf, 3);

            inputBlock[0] = (ulong)position.Pass;
            inputBlock[1] = (ulong)position.Lane;
            inputBlock[2] = (ulong)position.Slice;
            inputBlock[3] = (ulong)_memoryBlockCount;
            inputBlock[4] = (ulong)_timeCost;
            inputBlock[5] = (ulong)Addressing;
            for (var i = 0; i < _segmentLength; ++i)
            {
                if (i % _qwordsInBlock == 0)
                {
                    inputBlock[6] += 1;
                    tmpBlock.Init(0);
                    addressBlock.Init(0);
                    FillBlockWithXor(zeroBlock, inputBlock, tmpBlock);
                    FillBlockWithXor(zeroBlock, tmpBlock, addressBlock);
                }

                pseudoRands[i] = addressBlock[i % _qwordsInBlock];
            }
        }

        private void FillBlock(Block prevBlock, Block refBlock, Block nextBlock)
        {
            var buf = new ulong[_qwordsInBlock * 2];
            var blockR = new Block(buf, 0);
            var blockTmp = new Block(buf, 1);
            blockR.CopyXor(refBlock, prevBlock);
            blockTmp.Copy(blockR);

            // apply Blake2 on columns of 64-bit words:
            //    (0,1,...,15), then
            //    (16,17,..31)... finally
            //    (112,113,...127)
            for (var i = 0; i < 8; ++i)
            {
                var v0 = blockR[16 * i];
                var v1 = blockR[(16 * i) + 1];
                var v2 = blockR[(16 * i) + 2];
                var v3 = blockR[(16 * i) + 3];
                var v4 = blockR[(16 * i) + 4];
                var v5 = blockR[(16 * i) + 5];
                var v6 = blockR[(16 * i) + 6];
                var v7 = blockR[(16 * i) + 7];
                var v8 = blockR[(16 * i) + 8];
                var v9 = blockR[(16 * i) + 9];
                var v10 = blockR[(16 * i) + 10];
                var v11 = blockR[(16 * i) + 11];
                var v12 = blockR[(16 * i) + 12];
                var v13 = blockR[(16 * i) + 13];
                var v14 = blockR[(16 * i) + 14];
                var v15 = blockR[(16 * i) + 15];
                BlakeRoundNoMsg(
                    ref v0,
                    ref v1,
                    ref v2,
                    ref v3,
                    ref v4,
                    ref v5,
                    ref v6,
                    ref v7,
                    ref v8,
                    ref v9,
                    ref v10,
                    ref v11,
                    ref v12,
                    ref v13,
                    ref v14,
                    ref v15);
                blockR[16 * i] = v0;
                blockR[(16 * i) + 1] = v1;
                blockR[(16 * i) + 2] = v2;
                blockR[(16 * i) + 3] = v3;
                blockR[(16 * i) + 4] = v4;
                blockR[(16 * i) + 5] = v5;
                blockR[(16 * i) + 6] = v6;
                blockR[(16 * i) + 7] = v7;
                blockR[(16 * i) + 8] = v8;
                blockR[(16 * i) + 9] = v9;
                blockR[(16 * i) + 10] = v10;
                blockR[(16 * i) + 11] = v11;
                blockR[(16 * i) + 12] = v12;
                blockR[(16 * i) + 13] = v13;
                blockR[(16 * i) + 14] = v14;
                blockR[(16 * i) + 15] = v15;
            }

            // Apply Blake2 on rows of 64-bit words:
            // (0,1,16,17,...112,113), then
            // (2,3,18,19,...,114,115).. finally
            // (14,15,30,31,...,126,127)
            for (var i = 0; i < 8; ++i)
            {
                var v0 = blockR[2 * i];
                var v1 = blockR[(2 * i) + 1];
                var v2 = blockR[(2 * i) + 16];
                var v3 = blockR[(2 * i) + 17];
                var v4 = blockR[(2 * i) + 32];
                var v5 = blockR[(2 * i) + 33];
                var v6 = blockR[(2 * i) + 48];
                var v7 = blockR[(2 * i) + 49];
                var v8 = blockR[(2 * i) + 64];
                var v9 = blockR[(2 * i) + 65];
                var v10 = blockR[(2 * i) + 80];
                var v11 = blockR[(2 * i) + 81];
                var v12 = blockR[(2 * i) + 96];
                var v13 = blockR[(2 * i) + 97];
                var v14 = blockR[(2 * i) + 112];
                var v15 = blockR[(2 * i) + 113];
                BlakeRoundNoMsg(
                    ref v0,
                    ref v1,
                    ref v2,
                    ref v3,
                    ref v4,
                    ref v5,
                    ref v6,
                    ref v7,
                    ref v8,
                    ref v9,
                    ref v10,
                    ref v11,
                    ref v12,
                    ref v13,
                    ref v14,
                    ref v15);
                blockR[2 * i] = v0;
                blockR[(2 * i) + 1] = v1;
                blockR[(2 * i) + 16] = v2;
                blockR[(2 * i) + 17] = v3;
                blockR[(2 * i) + 32] = v4;
                blockR[(2 * i) + 33] = v5;
                blockR[(2 * i) + 48] = v6;
                blockR[(2 * i) + 49] = v7;
                blockR[(2 * i) + 64] = v8;
                blockR[(2 * i) + 65] = v9;
                blockR[(2 * i) + 80] = v10;
                blockR[(2 * i) + 81] = v11;
                blockR[(2 * i) + 96] = v12;
                blockR[(2 * i) + 97] = v13;
                blockR[(2 * i) + 112] = v14;
                blockR[(2 * i) + 113] = v15;
            }

            nextBlock.Copy(blockTmp);
            nextBlock.Xor(blockR);
        }

        private void FillBlockWithXor(Block prevBlock, Block refBlock, Block nextBlock)
        {
            var buf = new ulong[_qwordsInBlock * 2];
            var blockR = new Block(buf, 0);
            var blockTmp = new Block(buf, 1);
            blockR.CopyXor(refBlock, prevBlock);
            blockTmp.Copy(blockR);
            blockTmp.Xor(nextBlock); // saving the next block for XOR over

            // apply Blake2 on columns of 64-bit words:
            //    (0,1,...,15), then
            //    (16,17,..31)... finally
            //    (112,113,...127)
            for (var i = 0; i < 8; ++i)
            {
                var v0 = blockR[16 * i];
                var v1 = blockR[(16 * i) + 1];
                var v2 = blockR[(16 * i) + 2];
                var v3 = blockR[(16 * i) + 3];
                var v4 = blockR[(16 * i) + 4];
                var v5 = blockR[(16 * i) + 5];
                var v6 = blockR[(16 * i) + 6];
                var v7 = blockR[(16 * i) + 7];
                var v8 = blockR[(16 * i) + 8];
                var v9 = blockR[(16 * i) + 9];
                var v10 = blockR[(16 * i) + 10];
                var v11 = blockR[(16 * i) + 11];
                var v12 = blockR[(16 * i) + 12];
                var v13 = blockR[(16 * i) + 13];
                var v14 = blockR[(16 * i) + 14];
                var v15 = blockR[(16 * i) + 15];
                BlakeRoundNoMsg(
                    ref v0,
                    ref v1,
                    ref v2,
                    ref v3,
                    ref v4,
                    ref v5,
                    ref v6,
                    ref v7,
                    ref v8,
                    ref v9,
                    ref v10,
                    ref v11,
                    ref v12,
                    ref v13,
                    ref v14,
                    ref v15);
                blockR[16 * i] = v0;
                blockR[(16 * i) + 1] = v1;
                blockR[(16 * i) + 2] = v2;
                blockR[(16 * i) + 3] = v3;
                blockR[(16 * i) + 4] = v4;
                blockR[(16 * i) + 5] = v5;
                blockR[(16 * i) + 6] = v6;
                blockR[(16 * i) + 7] = v7;
                blockR[(16 * i) + 8] = v8;
                blockR[(16 * i) + 9] = v9;
                blockR[(16 * i) + 10] = v10;
                blockR[(16 * i) + 11] = v11;
                blockR[(16 * i) + 12] = v12;
                blockR[(16 * i) + 13] = v13;
                blockR[(16 * i) + 14] = v14;
                blockR[(16 * i) + 15] = v15;
            }

            // Apply Blake2 on rows of 64-bit words:
            // (0,1,16,17,...112,113), then
            // (2,3,18,19,...,114,115).. finally
            // (14,15,30,31,...,126,127)
            for (var i = 0; i < 8; ++i)
            {
                var v0 = blockR[2 * i];
                var v1 = blockR[(2 * i) + 1];
                var v2 = blockR[(2 * i) + 16];
                var v3 = blockR[(2 * i) + 17];
                var v4 = blockR[(2 * i) + 32];
                var v5 = blockR[(2 * i) + 33];
                var v6 = blockR[(2 * i) + 48];
                var v7 = blockR[(2 * i) + 49];
                var v8 = blockR[(2 * i) + 64];
                var v9 = blockR[(2 * i) + 65];
                var v10 = blockR[(2 * i) + 80];
                var v11 = blockR[(2 * i) + 81];
                var v12 = blockR[(2 * i) + 96];
                var v13 = blockR[(2 * i) + 97];
                var v14 = blockR[(2 * i) + 112];
                var v15 = blockR[(2 * i) + 113];
                BlakeRoundNoMsg(
                    ref v0,
                    ref v1,
                    ref v2,
                    ref v3,
                    ref v4,
                    ref v5,
                    ref v6,
                    ref v7,
                    ref v8,
                    ref v9,
                    ref v10,
                    ref v11,
                    ref v12,
                    ref v13,
                    ref v14,
                    ref v15);
                blockR[2 * i] = v0;
                blockR[(2 * i) + 1] = v1;
                blockR[(2 * i) + 16] = v2;
                blockR[(2 * i) + 17] = v3;
                blockR[(2 * i) + 32] = v4;
                blockR[(2 * i) + 33] = v5;
                blockR[(2 * i) + 48] = v6;
                blockR[(2 * i) + 49] = v7;
                blockR[(2 * i) + 64] = v8;
                blockR[(2 * i) + 65] = v9;
                blockR[(2 * i) + 80] = v10;
                blockR[(2 * i) + 81] = v11;
                blockR[(2 * i) + 96] = v12;
                blockR[(2 * i) + 97] = v13;
                blockR[(2 * i) + 112] = v14;
                blockR[(2 * i) + 113] = v15;
            }

            nextBlock.Copy(blockTmp);
            nextBlock.Xor(blockR);
        }

        private void BlakeRoundNoMsg(
            ref ulong v0,
            ref ulong v1,
            ref ulong v2,
            ref ulong v3,
            ref ulong v4,
            ref ulong v5,
            ref ulong v6,
            ref ulong v7,
            ref ulong v8,
            ref ulong v9,
            ref ulong v10,
            ref ulong v11,
            ref ulong v12,
            ref ulong v13,
            ref ulong v14,
            ref ulong v15)
        {
            G(ref v0, ref v4, ref v8, ref v12);
            G(ref v1, ref v5, ref v9, ref v13);
            G(ref v2, ref v6, ref v10, ref v14);
            G(ref v3, ref v7, ref v11, ref v15);
            G(ref v0, ref v5, ref v10, ref v15);
            G(ref v1, ref v6, ref v11, ref v12);
            G(ref v2, ref v7, ref v8, ref v13);
            G(ref v3, ref v4, ref v9, ref v14);
        }

        private void G(ref ulong a, ref ulong b, ref ulong c, ref ulong d)
        {
            a = FblaMka(a, b);
            d = Rotr64(d ^ a, 32);
            c = FblaMka(c, d);
            b = Rotr64(b ^ c, 24);
            a = FblaMka(a, b);
            d = Rotr64(d ^ a, 16);
            c = FblaMka(c, d);
            b = Rotr64(b ^ c, 63);
        }

        private ulong FblaMka(ulong x, ulong y)
        {
            return x + y + (2 * (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF));
        }

        private ulong Rotr64(ulong original, int bits)
        {
            return (original >> bits) | (original << (64 - bits));
        }

        private void Blake2BLong(byte[] hash, byte[] inbuf)
        {
            var outlenBytes = new byte[4];
            var outputLength = hash.Length > 64 ? 64 : hash.Length;
            using var intermediateHash = new PinnedMemory<byte>(new byte[64]);
            Store32(outlenBytes, hash.Length);
            using (var blakeHash = new Blake2b.NetCore.Blake2b(outputLength * 8))
            {
                blakeHash.UpdateBlock(outlenBytes, 0, outlenBytes.Length);
                blakeHash.UpdateBlock(inbuf, 0, inbuf.Length);
                blakeHash.DoFinal(intermediateHash, 0);
                blakeHash.Reset();
            }

            if (hash.Length <= intermediateHash.Length)
            {
                Array.Copy(intermediateHash.ToArray(), hash, hash.Length);
                return;
            }

            Array.Copy(intermediateHash.ToArray(), hash, 32);
            var pos = 32;
            var lastHashIndex = hash.Length - 64;
            var toHash = new byte[64];

            while (pos < lastHashIndex)
            {
                Array.Copy(intermediateHash.ToArray(), toHash, intermediateHash.Length);
                using var blakeHash = new Blake2b.NetCore.Blake2b(512);
                blakeHash.UpdateBlock(toHash, 0, toHash.Length);
                blakeHash.DoFinal(intermediateHash, 0);
                blakeHash.Reset();

                Array.Copy(intermediateHash.ToArray(), 0, hash, pos, 32);
                pos += 32;
            }

            Array.Copy(intermediateHash.ToArray(), toHash, intermediateHash.Length);
            var finalOutputLength = hash.Length - pos;
            using (var blakeHash = new Blake2b.NetCore.Blake2b(finalOutputLength * 8))
            {
                blakeHash.UpdateBlock(toHash, 0, toHash.Length);
                blakeHash.DoFinal(intermediateHash, 0);
                blakeHash.Reset();

                Array.Copy(intermediateHash.ToArray(), 0, hash, pos, finalOutputLength);
            }
        }

        private void Store32(byte[] buf, uint value)
        {
            buf[0] = (byte)value;
            buf[1] = (byte)(value >> 8);
            buf[2] = (byte)(value >> 16);
            buf[3] = (byte)(value >> 24);
        }

        private void Store32(byte[] buf, int value)
        {
            buf[0] = (byte)value;
            buf[1] = (byte)((uint)value >> 8);
            buf[2] = (byte)((uint)value >> 16);
            buf[3] = (byte)((uint)value >> 24);
        }

        private void Store32(byte[] buf, int offset, int value)
        {
            buf[0 + offset] = (byte)value;
            buf[1 + offset] = (byte)((uint)value >> 8);
            buf[2 + offset] = (byte)((uint)value >> 16);
            buf[3 + offset] = (byte)((uint)value >> 24);
        }

        private void Store64(byte[] buf, int offset, ulong value)
        {
            buf[0 + offset] = (byte)value;
            buf[1 + offset] = (byte)(value >> 8);
            buf[2 + offset] = (byte)(value >> 16);
            buf[3 + offset] = (byte)(value >> 24);
            buf[4 + offset] = (byte)(value >> 32);
            buf[5 + offset] = (byte)(value >> 40);
            buf[6 + offset] = (byte)(value >> 48);
            buf[7 + offset] = (byte)(value >> 56);
        }

        private void StoreBlock(byte[] buf, Block blockValues)
        {
            if (BitConverter.IsLittleEndian)
            {
                var destWords = MemoryMarshal.Cast<byte, ulong>(buf.AsSpan(0, _blockSize));
                blockValues.CopyTo(destWords);
                return;
            }

            for (var i = 0; i < _qwordsInBlock; ++i)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(8 * i, 8), blockValues[i]);
            }
        }

        private ulong Load64(byte[] value, int offset)
        {
            return value[offset]
                | ((ulong)value[offset + 1] << 8)
                | ((ulong)value[offset + 2] << 16)
                | ((ulong)value[offset + 3] << 24)
                | ((ulong)value[offset + 4] << 32)
                | ((ulong)value[offset + 5] << 40)
                | ((ulong)value[offset + 6] << 48)
                | ((ulong)value[offset + 7] << 56);
        }

        private void LoadBlock(Block dst, byte[] src)
        {
            if (BitConverter.IsLittleEndian)
            {
                var srcWords = MemoryMarshal.Cast<byte, ulong>(src.AsSpan(0, _blockSize));
                dst.CopyFrom(srcWords);
                return;
            }

            for (var i = 0; i < _qwordsInBlock; ++i)
            {
                dst[i] = BinaryPrimitives.ReadUInt64LittleEndian(src.AsSpan(i * 8, 8));
            }
        }

        private class Position
        {
            public int Pass { get; set; }
            public int Lane { get; set; }
            public int Slice { get; set; }
            public int Index { get; set; }
        }

        private class Blocks
        {
            private readonly Block[] blockValues;
            public Blocks(ulong[] memory, int blockCount)
            {
                blockValues = Enumerable.Range(0, blockCount).Select(i => new Block(memory, i)).ToArray();
            }

            public Block this[int i] => this.blockValues[i];
        }

        private class Block
        {
            private readonly ulong[] memory;
            private readonly int offset;

            public Block(ulong[] memory, int blockIndex)
            {
                this.memory = memory;
                this.offset = blockIndex * _qwordsInBlock;
            }

            public ulong this[int i]
            {
                get => this.memory[this.offset + i];
                set => this.memory[this.offset + i] = value;
            }

            public Span<ulong> AsSpan()
            {
                return this.memory.AsSpan(this.offset, _qwordsInBlock);
            }

            public void Copy(Block other)
            {
                other.AsSpan().CopyTo(AsSpan());
            }

            public void Xor(Block other)
            {
                XorSpans(AsSpan(), other.AsSpan());
            }

            public void CopyXor(Block left, Block right)
            {
                CopyXorSpans(AsSpan(), left.AsSpan(), right.AsSpan());
            }

            public void CopyTo(Span<ulong> destination)
            {
                AsSpan().CopyTo(destination);
            }

            public void CopyFrom(ReadOnlySpan<ulong> source)
            {
                source.CopyTo(AsSpan());
            }

            public void Init(ulong value)
            {
                for (var i = 0; i < _qwordsInBlock; ++i)
                {
                    this[i] = value;
                }
            }

            private static void XorSpans(Span<ulong> destination, ReadOnlySpan<ulong> source)
            {
                var vectorWidth = Vector<ulong>.Count;
                var i = 0;

                if (Vector.IsHardwareAccelerated && destination.Length >= vectorWidth)
                {
                    for (; i <= destination.Length - vectorWidth; i += vectorWidth)
                    {
                        var vDest = new Vector<ulong>(destination.Slice(i, vectorWidth));
                        var vSrc = new Vector<ulong>(source.Slice(i, vectorWidth));
                        (vDest ^ vSrc).CopyTo(destination.Slice(i, vectorWidth));
                    }
                }

                for (; i < destination.Length; ++i)
                {
                    destination[i] ^= source[i];
                }
            }

            private static void CopyXorSpans(Span<ulong> destination, ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
            {
                var vectorWidth = Vector<ulong>.Count;
                var i = 0;

                if (Vector.IsHardwareAccelerated && destination.Length >= vectorWidth)
                {
                    for (; i <= destination.Length - vectorWidth; i += vectorWidth)
                    {
                        var vLeft = new Vector<ulong>(left.Slice(i, vectorWidth));
                        var vRight = new Vector<ulong>(right.Slice(i, vectorWidth));
                        (vLeft ^ vRight).CopyTo(destination.Slice(i, vectorWidth));
                    }
                }

                for (; i < destination.Length; ++i)
                {
                    destination[i] = left[i] ^ right[i];
                }
            }
        }

        public void Dispose()
        {
            _memory?.Dispose();
            _key?.Dispose();
            _associatedDataPin?.Dispose();

            ClearBuffer();
        }
    }
}
