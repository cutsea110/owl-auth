module Yesod.Auth.Owl.Auth
       ( OwlRes(..)
       , AuthReq(..)
       , AuthRes(..)
       ) where

import Control.Applicative ((<$>),(<*>))
import Control.Monad (mzero)
import Data.Aeson
import qualified Data.ByteString.Lazy.Char8 as LB
import Data.HashMap.Strict as M (toList)
import Data.Text (Text)
import Yesod.Auth.Owl.Internal.Res (OwlRes(..))

-- Request for Authentication API
data AuthReq = AuthReq
               { ident :: Text
               , pass :: Text
               }
             deriving (Show, Read, Eq)

instance FromJSON AuthReq where
  parseJSON (Object v) = AuthReq <$> v .: "ident" <*> v .: "pass"
  parseJSON _ = mzero
instance ToJSON AuthReq where
  toJSON (AuthReq i p) = object ["ident" .= i, "pass" .= p]

-- Response for Authentication API
data AuthRes = Rejected
               { rejected_ident :: Text
               , rejected_pass :: Text
               , rejected_reason :: Text
               }
             | Accepted
               { accepted_ident :: Text
               , accepted_email :: Maybe Text
               }
             deriving (Show, Read, Eq)

instance FromJSON AuthRes where
  parseJSON (Object o) = case M.toList o of
    [("rejected", Object o')] ->
      Rejected <$> o' .: "ident" <*> o' .: "pass" <*> o' .: "reason"
    [("accepted", Object o')] ->
      Accepted <$> o' .: "ident" <*> o' .:? "email"
    _ -> mzero
  parseJSON _ = mzero

instance ToJSON AuthRes where
  toJSON (Rejected i p r) = object [ "rejected" .= object [ "ident" .= i
                                                          , "pass" .= p
                                                          , "reason" .= r
                                                          ]
                                   ]
  toJSON (Accepted i me) = object [ "accepted" .= object [ "ident" .= i
                                                         , "email" .= me
                                                         ]
                                  ]
