module Network.HaskellNet.Auth
where

import qualified Codec.Binary.Base64.String as B64 (decode, encode)
import           Crypto.Hash.MD5
import           Data.Array
import           Data.Bits
import qualified Data.ByteString            as B
import           Data.List
import           Data.Word

type UserName = String

-- | Password. In case of OAuth2, it is access token.
type Password = String

data AuthType = PLAIN
              | LOGIN
              | CRAM_MD5
              | OAUTH2
                deriving Eq

instance Show AuthType where
    showsPrec d at = showParen (d>app_prec) $ showString $ showMain at
        where app_prec = 10
              showMain PLAIN    = "PLAIN"
              showMain LOGIN    = "LOGIN"
              showMain CRAM_MD5 = "CRAM-MD5"
              showMain OAUTH2   = "OAUTH2"

b64Encode :: String -> String
b64Encode = map (toEnum.fromEnum) . B64.encode . map (toEnum.fromEnum)

b64Decode :: String -> String
b64Decode = map (toEnum.fromEnum) . B64.decode . map (toEnum.fromEnum)

showOctet :: [Word8] -> String
showOctet = concatMap hexChars
    where hexChars c = [arr ! (c `div` 16), arr ! (c `mod` 16)]
          arr = listArray (0, 15) "0123456789abcdef"

hashMD5 :: [Word8] -> [Word8]
hashMD5 = B.unpack . hash . B.pack

hmacMD5 :: String -> String -> [Word8]
hmacMD5 text key = hashMD5 $ okey ++ hashMD5 (ikey ++ map (toEnum.fromEnum) text)
    where koc = map (toEnum.fromEnum) key
          key' = if length koc > 64
                 then hashMD5 $ koc ++ replicate 48 0
                 else koc ++ replicate (64-length koc) 0
          ipad = replicate 64 0x36
          opad = replicate 64 0x5c
          ikey = zipWith xor key' ipad
          okey = zipWith xor key' opad

plain :: UserName -> Password -> String
plain user pass = b64Encode $ intercalate "\0" ["", user, pass]

login :: UserName -> Password -> (String, String)
login user pass = (b64Encode user, b64Encode pass)

cramMD5 :: String -> UserName -> Password -> String
cramMD5 challenge user pass =
    b64Encode (user ++ " " ++ showOctet (hmacMD5 challenge pass))

oauth2 :: UserName -> Password -> String
oauth2 user token =
    b64Encode $ concat ["user=", user, "\1", "auth=Bearer ", token, "\1\1"]

auth :: AuthType -> String -> UserName -> Password -> String
auth PLAIN    _ u p = plain u p
auth LOGIN    _ u p = let (u', p') = login u p in unwords [u', p']
auth CRAM_MD5 c u p = cramMD5 c u p
auth OAUTH2   _ u p = oauth2 u p
