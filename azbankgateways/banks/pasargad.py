import logging
import json
import datetime
import jdatetime
import requests

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA1
from base64 import b64encode, b64decode

from azbankgateways.banks import BaseBank
from azbankgateways.exceptions import SettingDoesNotExist, BankGatewayConnectionError
from azbankgateways.exceptions.exceptions import BankGatewayRejectPayment
from azbankgateways.models import CurrencyEnum, BankType, PaymentStatus


class PASARGAD(BaseBank):
    """ Define class-related parameters 

    parameters read from the project settings.py file 
    """
    _merchantname = None
    _merchantcode = None
    _terminalcode = None
    _pemcode = None
    _actioncode = None

    def __init__(self, **kwargs):
        """ Update the parameters with the url related to the banking gateway 

        : url param
        token
        payment
        transaction
        verify
        """
        super().__init__(**kwargs)
        self.set_gateway_currency(CurrencyEnum.IRT)
        self._get_token_url = 'https://pep.shaparak.ir/Api/v1/Payment/GetToken'
        self._get_payment_url = 'https://pep.shaparak.ir/payment.aspx'
        self._get_transaction_url = "https://pep.shaparak.ir/Api/v1/Payment/CheckTransactionResult"
        self._get_verify_url = "https://pep.shaparak.ir/Api/v1/Payment/VerifyPayment"

    def get_bank_type(self):
        """ Send bank type

        designation of pasargad bank as the type of bank
        """
        return BankType.PASARGAD

    def set_default_settings(self):
        """ Read the value of the parameters from the project settings.py file
        
        Update parameter values from the project settings.py file 
        """
        for item in ['MERCHANT_NAME', 'MERCHANT_CODE', 'TERMINAL_CODE', 'PATH_CODE', 'ACTION_CODE']:
            if item not in self.default_setting_kwargs:
                raise SettingDoesNotExist()
            setattr(self, f'_{item.lower()}', self.default_setting_kwargs[item])

    """
    : payment
    """    

    def get_pay_data(self):
        """Value the parameters
        
        value the parameters related to the bank to receive tokens from pasargad bank 
        """
        data = {
            "InvoiceNumber": self.get_tracking_code(),
            "InvoiceDate": self._get_current_date(),
            "MerchantCode": self._merchantcode,
            "TerminalCode": self._terminalcode,
            "Amount": self.get_gateway_amount(),
            "RedirectAddress": self._get_gateway_callback_url(),
            "TimeStamp": self._get_timestamp(),
            "Action": self._actioncode,
            "Mobile": self.get_mobile_number(),
            "MerchantName": self._merchantname
        }
        return json.dumps(data)

    def prepare_pay(self):
        super(PASARGAD, self).prepare_pay()

    def pay(self):
        """Receive token
        
        sending a request to the bank to receive a token 
        in order to send the user to pasargad bank gateway  
        """
        super(PASARGAD, self).pay()
        api = self._get_token_url
        data = self.get_pay_data()
        headers  = self._get_headers(data)
        response = self._send_data(api, data, headers)        
        if response['IsSuccess']:
            token = response['Token']
            self._set_reference_number(token)
        else:
            logging.critical("PASARGAD gateway reject payment")
            raise BankGatewayRejectPayment(self.get_transaction_status_text())

    """
    : gateway
    """

    @classmethod
    def get_minimum_amount(cls):
        """Define the minimum amount 
        
        definition of the minimum amount that pasargad bank accepts for purchase  
        """
        return 5000

    def _get_gateway_payment_url_parameter(self):
        """Determining the url of pasargad bank
        
        determining the url of pasargad bank payment gateway 
        in order to send the user to the gateway by the package  
        """
        return self._get_payment_url    

    def _get_gateway_payment_method_parameter(self):
        """Determining the method
        
        determining the method of sending pasargad bank payment gateway parameters 
        for the package
        """
        return 'GET'

    def _get_gateway_payment_parameter(self):
        """Determining the parameters
        
        determining the necessary parameters in order to 
        send the user to the payment gateway of pasargad bank for the package 
        """
        params = {
            'n': self.get_reference_number()
        }
        return params

    """
    : verify from gateway
    """

    def prepare_verify_from_gateway(self):
        """ Prepare verify from gateway
        
        update the parameters of the bank object with the returned results 
        of the transaction that was successfully completed 
        """
        super(PASARGAD, self).prepare_verify_from_gateway()
        request = self.get_request()
        tracking_code = request.GET.get('iN', None)
        tref_date = request.GET.get('iD', None)
        tref_num = request.GET.get('tref', None)
        self._set_tracking_code(tracking_code) 
        setattr(self, '_get_invoice_date', tref_date)       
        response = self._transaction_result(tref_num, tref_date) 
        ref_num = response['transactionReferenceID']               
        self._set_bank_record()                
        if ref_num and response['result'] and \
            self.get_gateway_amount == response['amount']:                      
            self._set_reference_number(ref_num)
            self._bank.reference_number = ref_num
            self._bank.extra_information = json.dumps(response)
            self._bank.save()

    def verify_from_gateway(self, request):
        super(PASARGAD, self).verify_from_gateway(request)

    """
    : transaction result from gateway
    """

    def _get_trans_data(self, transaction_code, transaction_date):
        """ Value the parameters
        
        value the parameters related to the bank to receive transaction result from pasargad bank 
        """
        transaction = {
            "TransactionReferenceID" : transaction_code,
            "InvoiceNumber" : self.get_tracking_code,
            "InvoiceDate" : transaction_date,
            "MerchantCode" : self._merchantcode,
            "TerminalCode" : self._terminalcode,
            "Mobile" :  self.get_mobile_number,
            "MerchantName" : self._merchantname,
        }
        return json.dumps(transaction)
    
    def _transaction_result(self, transaction_code, transaction_date):
        """ Receive transaction result
        
        send a request to the bank to receive the result of the transaction
        in order to update the bank object 
          
        """
        api = self._get_transaction_url
        data = self._get_trans_data(transaction_code, transaction_date)
        headers  = self._get_headers()
        response = self._send_data(api, data, headers)
        return response
    
    """
    : verify
    """

    def get_verify_data(self):
        """ Value the parameters
        
        bank-related parameters to confirm payment by pasargad bank 
        """
        super(PASARGAD, self).get_verify_data()
        data = {
            "InvoiceNumber" : self._get_tracking_code(),
            "InvoiceDate" : self._get_invoice_date,
            "MerchantCode" : self._merchantcode,
            "TerminalCode" : self._terminalcode,
            "Amount" : self.get_gateway_amount(),
            "TimeStamp" : self._get_timestamp(),
        }
        return json.dumps(data)

    def prepare_verify(self, tracking_code):
        super(PASARGAD, self).prepare_verify(tracking_code)

    def verify(self, transaction_code):
        """ Verify the payment by the bank
        
        send a request to confirm the payment by the bank and
        determine the payment status in the bank object 
        """
        super(PASARGAD, self).verify(transaction_code)
        api = self._get_verify_url
        data = self.get_verify_data()
        headers  = self._get_headers(self, data)
        response = self._send_data(api, data, headers)       
        if response['IsSuccess']:
            self._set_payment_status(PaymentStatus.COMPLETE)
        else:
            self._set_payment_status(PaymentStatus.CANCEL_BY_USER)
            logging.debug("SEP gateway unapprove payment")

    def _send_data(self, api, data, headers):
        """ Send request
        
        send the desired requests to the bank 
        """
        try:
            response = requests.request(
                method='POST',
                url=api,
                data=data,
                headers=headers,
                timeout=5
            )
        except requests.Timeout:
            logging.exception("PASARGAD time out gateway {}".format(data))
            raise BankGatewayConnectionError()
        except requests.ConnectionError:
            logging.exception("PASARGAD time out gateway {}".format(data))
            raise BankGatewayConnectionError()

        response_json = json.loads(response.text)
        self._set_transaction_status_text(response_json.get('IsSuccesse'))
        return response_json    

    def _get_headers(self, data=None):
        """ Define header 
        
        definition of the header with a digital signature 
        in order for the requests to be valid by Pasargad Bank 
        """
        headers = {
            'Content-Type': "application/json",
        }
        if data is not None:
            signature = self._get_signature_data(data)
            headers['Sign'] = signature        
        return headers

    def _get_signature_data(self, data):
        """ Create signature base on data with pem key

        : param
        private_key_loc Path to your private key (pem key)
        package Data to be signed

        : return
        base64 encoded signature
        """
        key_base64 = b64decode(self._pemcode)
        rsa_key = RSA.importKey(key_base64)
        signer = PKCS1_v1_5.new(rsa_key)
        digest = SHA1.new()
        encode_data = bytes(data.encode())
        digest.update(encode_data)
        sign = signer.sign(digest)
        signature = b64encode(sign)
        return signature    

    @staticmethod
    def _get_current_date():
        """ Get the current date and time to the persian date """
        return jdatetime.datetime.now().strftime("%Y-%m-%d")

    @staticmethod
    def _get_timestamp():
        """ Get the current date and time to the gregorian date """
        return datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")


