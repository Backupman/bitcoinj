/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.machinecoin;

import com.google.bitcoin.core.*;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptOpCodes;
import com.lambdaworks.crypto.SCrypt;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class MachinecoinParams extends NetworkParameters {
    public MachinecoinParams() {
        super();
        id = "org.machinecoin.production";
        proofOfWorkLimit = Utils.decodeCompactBits(0x1e0fffffL);
        addressHeader = 50;
        acceptableAddressCodes = new int[] { 50 };
        port = 40333;
        packetMagic = 0xfbc0b6dbL;
        dumpedPrivateKeyHeader = 128 + addressHeader;

        targetTimespan = (int)(3.5 * 24 * 60 * 60);
        interval = targetTimespan/((int)(2.5 * 60));

        genesisBlock.setDifficultyTarget(0x1e0ffff0L);
        genesisBlock.setTime(1389040865L);
        genesisBlock.setNonce(3716037L);
        genesisBlock.removeTransaction(0);
        Transaction t = new Transaction(this);
        try {
            // A script containing the difficulty bits and the following message:
            //
            //   "Der Tagesspiegel 06/Jan/2014 Henry Maske, famous fighter, is now 50 years old"
            byte[] bytes = Hex.decode
                    ("04ffff001d01044c4d4465722054616765737370696567656c2030362f4a616e2f323031342048656e7279204d61736b652c2066616d6f757320666967687465722c206973206e6f77203530207965617273206f6c64");
            t.addInput(new TransactionInput(this, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode
                    ("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(this, t, Utils.toNanoCoins(50, 0), scriptPubKeyBytes.toByteArray()));
        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        genesisBlock.addTransaction(t);
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("6a1f879bcea5471cbfdee1fd0cb2ddcc4fed569a500e352d41de967703e83172"),
                genesisBlock);

        subsidyDecreaseBlockCount = 840000;

        dnsSeeds = new String[] {
                "dnsseed.machinecoin.org"
        };
    }

    private static BigInteger MAX_MONEY = Utils.COIN.multiply(BigInteger.valueOf(84000000));
    @Override
    public BigInteger getMaxMoney() { return MAX_MONEY; }

    private static MachinecoinParams instance;
    public static synchronized MachinecoinParams get() {
        if (instance == null) {
            instance = new MachinecoinParams();
        }
        return instance;
    }

    /** The number of previous blocks to look at when calculating the next Block's difficulty */
    @Override
    public int getRetargetBlockCount(StoredBlock cursor) {
        if (cursor.getHeight() + 1 != getInterval()) {
            //Logger.getLogger("wallet_mac").info("Normal MAC retarget");
            return getInterval();
        } else {
            //Logger.getLogger("wallet_mac").info("Genesis MAC retarget");
            return getInterval() - 1;
        }
    }

    @Override public String getURIScheme() { return "machinecoin:"; }

    /** Gets the hash of the given block for the purpose of checking its PoW */
    public Sha256Hash calculateBlockPoWHash(Block b) {
        byte[] blockHeader = b.cloneAsHeader().bitcoinSerialize();
        try {
            return new Sha256Hash(Utils.reverseBytes(SCrypt.scrypt(blockHeader, blockHeader, 1024, 1, 1, 32)));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        NetworkParameters.registerParams(get());
        NetworkParameters.PROTOCOL_VERSION = 70002;
    }
}
