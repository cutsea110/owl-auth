module Yesod.Auth.Owl.Internal.Res where

import Control.Applicative ((<$>),(<*>))
import Control.Monad (mzero)
import Data.Aeson
import qualified Data.Text.Lazy  as TL
import qualified Data.ByteString.Lazy.Char8 as LB
import qualified Data.Text.Lazy.Encoding as TE
import qualified Data.ByteString.Base64.Lazy as Base64

encodeToText :: LB.ByteString -> TL.Text
encodeToText = TE.decodeUtf8 . Base64.encode

decodeFromText :: (Monad m) => TL.Text -> m LB.ByteString
decodeFromText = either fail return . Base64.decode . TE.encodeUtf8

data OwlRes = OwlRes { cipher :: LB.ByteString } deriving Show
instance FromJSON OwlRes where
  parseJSON (Object o) = OwlRes <$> ((o .: "cipher") >>= decodeFromText)
  parseJSON _ = mzero
instance ToJSON OwlRes where
  toJSON (OwlRes e) = object [ "cipher" .= encodeToText e ]
