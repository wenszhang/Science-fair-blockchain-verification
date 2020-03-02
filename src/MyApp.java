import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Optional;

public class MyApp {

    public static ArrayList<Block> blockchain = new ArrayList<Block>();
    public static int difficulty = 1;

    public static void main(String[] args) {
        HashMap<String, Diploma> idMap = new HashMap<>();
        try {
            // create a block chain
            BlockData blockData1 = new BlockData("BYU");
            Block block1 = new Block(blockData1, "0");
            addBlock(block1);

            BlockData blockData2 = new BlockData("UofU");
            Block block2 = new Block(blockData2, blockchain.get(blockchain.size()-1).getHash());
            addBlock(block2);

            BlockData blockData3 = new BlockData("UVU");
            Block block3 = new Block(blockData3, blockchain.get(blockchain.size()-1).getHash());
            addBlock(block3);

            // create a diploma
            Diploma diploma1 = new Diploma("Wensen Zhang", 123456, new Date(), DEGREE_TYPE.BACHELOR,
                    "UofU", blockData2.getUniversityPublicKey(), block1.getHash());
            // add diploma to university block
            blockData2.getDiplomaPublicKeyMap().put(diploma1.getMapKey(), diploma1.getPublicKey());

            Boolean isValid = isDiplomaValid(diploma1);
            System.out.println("Diploma validation is " + isValid);

            Diploma fakeDiploma = new Diploma("Wensen Zhang", 123456, new Date(), DEGREE_TYPE.BACHELOR,
                    "UofU1", blockData2.getUniversityPublicKey(), block1.getHash());
            Boolean shouldBeFalse = isDiplomaValid(fakeDiploma);
            System.out.println("fakeDiploma validation is " + shouldBeFalse);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static Boolean isDiplomaValid(Diploma diploma) throws Exception {
        Optional<Block> foundBlock;
        foundBlock = blockchain.stream().filter(x -> x.getBlockData().getUniversityName().equals(diploma.getUniversityName())).findFirst();
        // first validate block hash
        if(foundBlock.isPresent()) {
            Block currentBlock = foundBlock.get();
            // check block hash
            if(!currentBlock.getHash().equals(currentBlock.calculateHash())){
                return false;
            }
            // check next block hash
            if(!diploma.getPreviousHash().equals(currentBlock.getPreviousHash())){
                return false;
            }
            // check data
            String decryptedDiploma = currentBlock.getBlockData().getDecryptedDiploma(
                    diploma.getEncryptedDiploma(), currentBlock.getBlockData().getDiplomaPublicKeyMap().get(diploma.getMapKey()));
            if(decryptedDiploma.equals(diploma.toString())){
                return true;
            }
            System.out.println("decryptedDiploma is " + decryptedDiploma);
        }
        return false;
    }

    public static Boolean isChainValid() {
        Block currentBlock;
        Block previousBlock;
        String hashTarget = new String(new char[difficulty]).replace('\0', '0');

        //loop through blockchain to check hashes:
        for(int i=1; i < blockchain.size(); i++) {
            currentBlock = blockchain.get(i);
            previousBlock = blockchain.get(i-1);
            //compare registered hash and calculated hash:
            if(!currentBlock.getHash().equals(currentBlock.calculateHash()) ){
                System.out.println("Current Hashes not equal");
                return false;
            }
            //compare previous hash and registered previous hash
            if(!previousBlock.getHash().equals(currentBlock.getPreviousHash()) ) {
                System.out.println("Previous Hashes not equal");
                return false;
            }
            //check if hash is solved
            if(!currentBlock.getHash().substring( 0, difficulty).equals(hashTarget)) {
                System.out.println("This block hasn't been mined");
                return false;
            }
            try {
                System.out.println("!!!!!!!!!!The Node data is: " + currentBlock.getDataBack());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return true;
    }

    public static void addBlock(Block newBlock) {
        newBlock.mineBlock(difficulty);
        blockchain.add(newBlock);
    }
}
