/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**
*@file dcmjsonparser.c
*
*@brief Types and APIs exposed by dcm.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>
#include <errno.h>
#include <telemetry_busmessage_sender.h>
#include "safec_lib.h"


/**
 * @defgroup DCM  DCM (Device Configuration Management)
 *
 * - This component parses Device Configuration Management JSON responses.
 *
 * @image html DCM.png
 * @defgroup DCM_API DCM Public APIs
 * @ingroup DCM
 *
 * @defgroup DCM_TYPES DCM Data Types
 * Data types defined for RFC(Remote Feature Control).
 * @ingroup  DCM
 */

/**
 * @addtogroup DCM_TYPES
 * @{
 */

#define RFC_CONFIG_DATA "/tmp/rfc_configdata.txt" //!<  Contains Configured data’s that are parsed to the client.
#define RFC_SSH_CONFIG_DATA "/tmp/RFC/.RFC_SSHWhiteList.list" //!< Contains the list of IPs obtained from RFC feature control at startup.
/**
 * @}
 */


/**
 * @addtogroup DCM_API
 * @{
 */

/**
 * @brief This function takes a cJSON node as argument and verifies whether the supplied argument is an node array.
 *
 * @param[in] item      item to know its type.
 *
 * @retval Returns 1 if the supplied item is an array kind otherwise returns 0.
 */
int isNodeArrayType(cJSON * const item)
{
    if (item == NULL)
    {
        return 0;
    }

    return (item->type & 0xFF) == cJSON_Array;
}

/**
 * @brief This function writes the parsed JSON information to a file.
 *
 * @param[in] arrayNode     JSON array.
 * @param[in] filename      Name of the file where parsed data will be stored.
 *
 * @ret returns status(0/1).
 */
int saveToFile(cJSON * arrayNode, const char* filename)
{
    printf("dcmjsonparser: Entering %s\n", __FUNCTION__);
    int status = 0;
    FILE * fp;
    int i = 0;
    fp = fopen(filename,"w+");
    if(NULL != fp)
    {
        int arraySize = cJSON_GetArraySize(arrayNode);
        for(i =0;i<arraySize;i++)
        {
            cJSON * aItem = cJSON_GetArrayItem(arrayNode,i);
            status = fprintf(fp,"%s\n",aItem->valuestring);
            if(status <= 0)
                 printf("dcmjsonparser: %s:%d Warning failed to write to file %s \n",__FUNCTION__, __LINE__,strerror(errno));
        }
        fclose(fp);
        status = 1;
    }
    else
    {
        printf("dcmjsonparser: Failed to open %s : %s\n",filename,strerror(errno));
    }
    return status;
}

/**
 * @brief This function traverses through the cJSON node list and returns the next node that is an Array.
 *
 * @param[in] node JSON response from SSH whitelist.
 *
 * @ret returns  JSON array.
 */
cJSON* getArrayNode(cJSON *node)
{
        cJSON * arrayNode = NULL;
        while(NULL != node)
        {

                if(isNodeArrayType(node))
                {
                        arrayNode = node;
                        break;
                }
                else if (NULL != node->child)
                {
                        cJSON * childNode = getArrayNode(node->child);
                        if( NULL != childNode)
                        {
                                arrayNode = childNode;
                                break;
                        }
                }
                node = node->next;
        }
        return arrayNode;
}

/**
 * @brief This function processes IP and MAC lists configured in the feature list.
 *
 * -Example:
 *  {
 *              "name":"SNMPWhitelist",
 *              "effectiveImmediate":false,
 *              "enable":true,
 *              "configData":{},
 *              "listType":"IPv4",
 *              "listSize":5,
 *              "SNMP IP4 WL":["178.62.43.255","128.82.34.17","192.168.1.80","192.168.1.1/24","10.0.0.32/6"]
 *              },
 *
 * @param[in] sshFeature  Contains JSON values like List type and list size
 *
 */
void processSSHWhiteList(cJSON *sshFeature)
{
    printf("dcmjsonparser: Entering %s\n", __FUNCTION__);
    cJSON* childNode = getArrayNode(sshFeature);
    if(NULL != childNode)
    {
        if (1 == saveToFile(childNode, RFC_SSH_CONFIG_DATA))
            printf("dcmjsonparser: SSHWhiteList processed successfully\n");
    }
}

/**
 * @brief This function parses dcm JSON information and save it to a file.
 *
 * JSON will contain these information Feature control information like effectiveImmediate,configData.
 * - Example:In this main function "featureControl" JSON is created with features in KeyValue format.
 *
 *   FeatureControl
 *   {
 *    "features": [
 *     {
 *       "name": "<feature name>",
 *       "effectiveImmediate": true,
 *       "enable": true,
 *       "configData": {
         <Parameter to configure>
 *     }
 *       "listType": "B8:27:EB:50:C1:CF",
 *       "listSize": 1,
 *       "RDK_RPI": [
 *       "B8:27:EB:50:C1:FC"
 *       ]
 *    }
 *   ]
 *   }
 *
 */
void main(int argc, char **argv)
{
    char *data = NULL,*dcmResponse = NULL;
    cJSON *paramObj = NULL, *childObj = NULL,*json=NULL,*configData=NULL,*effectiveImmediate=NULL;
    FILE *fileRead = NULL,*fileWrite =NULL;

    long len;
    int i;
    errno_t rc = -1;
    int ind = -1;

    if(argc != 2)
    {
        printf("dcmjsonparser: Pass valid arguments \n");
        exit(0);
    }
    else
    {
        dcmResponse = argv[1];
    }

    t2_init("dcm-parser");

    printf("dcmjsonparser: dcm response file name %s\n",dcmResponse);
    
    fileRead = fopen( dcmResponse, "r+" );    
    if( fileRead == NULL ) 
    {
        printf( "dcmjsonparser: Error opening file in read mode\n" );
        exit(0);
    }
    
    fseek( fileRead, 0, SEEK_END );
    len = ftell( fileRead );
    fseek( fileRead, 0, SEEK_SET );
    data = ( char* )malloc( len + 1 );
    fread( data, 1, len, fileRead );
    fclose( fileRead );

    if( data != NULL ) 
    {
        json = cJSON_Parse( data );

        if( !json ) 
        {
            printf( "dcmjsonparser: json parse error: [%s]\n", cJSON_GetErrorPtr() );
            t2_event_d("SYS_INFO_WEBPA_Config_Corruption", 1);
        } 
        else 
        {
            printf( "dcmjsonparser: cjson parse success\n" );
            
            fileWrite=fopen(RFC_CONFIG_DATA,"w+");
            if(fileWrite ==NULL)
            {
                printf( "dcmjsonparser: Error opening file in write mode\n" );
                free(data);
                exit(0);
            }
            
            paramObj = cJSON_GetObjectItem( json, "featureControl" );
            if( paramObj != NULL ) 
            {
                cJSON * configset_id = cJSON_GetObjectItem( paramObj, "configset-id" );
                if(configset_id !=NULL)
                {
                    char *configset = cJSON_GetObjectItem( paramObj, "configset-id" )->valuestring;
                    if(configset !=NULL)
                    {
                        printf( "dcmjsonparser: configset-id is %s\n", configset );
                    }
                    else
                    {
                        printf( "dcmjsonparser: configset-id value is NULL\n");
                    }
                }
                else
                {
                    printf( "dcmjsonparser: configset-id not recieved in response\n");
                }
                cJSON * configset_label = cJSON_GetObjectItem( paramObj, "configset-label" );
                if(configset_label !=NULL)
                {
                    char *configset = cJSON_GetObjectItem( paramObj, "configset-label" )->valuestring;
                    if(configset !=NULL)
                    {
                        printf( "dcmjsonparser: configset-label is %s\n", configset );
                    }
                    else
                    {
                        printf( "dcmjsonparser: configset-label value is NULL\n");
                    }
                }
                else
                {
                    printf( "dcmjsonparser: configset-label not recieved in response\n");
                }
                
                childObj = cJSON_GetObjectItem( paramObj, "features" );
                if(childObj !=NULL)
                {
                    int subitemSize = cJSON_GetArraySize( childObj );
                    printf("dcmjsonparser: features array size is %d\n",subitemSize);
                    int length = strlen("sshwhitelist");
                    for( i = 0; i < subitemSize; i++ ) 
                    {
                        cJSON* subitem = cJSON_GetArrayItem( childObj, i );
                        cJSON* featureName = cJSON_GetObjectItem(subitem, "name" );
                        cJSON* listType =  cJSON_GetObjectItem(subitem, "listType");
                        if (featureName != NULL && listType != NULL)
                        {
                            rc = strcasecmp_s("sshwhitelist",length, featureName->valuestring, &ind);
                            ERR_CHK(rc);
                            if ((!ind) && (rc == EOK))
                            {
                                printf("dcmjsonparser: SSHWhiteList feature found!!\n");
                                processSSHWhiteList(subitem);
                            }
                        }

                        effectiveImmediate = cJSON_GetObjectItem( subitem, "effectiveImmediate" );
                        int effectiveImmediatevalue;
                        if(effectiveImmediate !=NULL)
                        {
                                effectiveImmediatevalue=effectiveImmediate->valueint;
                                printf("dcmjsonparser: effectiveImmediate is %d\n",effectiveImmediatevalue);
                        }
                        else
                        {
                                printf("dcmjsonparser: featureControl.features.effectiveImmediate object is not present\n");
                        }

                        configData = cJSON_GetObjectItem( subitem, "configData" );
                        if(configData !=NULL)
                        {
                            cJSON *configObject = configData->child;
                            while( configObject ) 
                            {
                                char *configKey = configObject->string;
                                char *configValue = configObject->valuestring;
                                printf("dcmjsonparser: key is %s\n",configKey); 
                                printf("dcmjsonparser: value is %s\n",configValue); 
                                if(strncmp(configKey,"tr181.",6)==0)
                                {
                                    /* #~ is used to seperate configKey,configValue,effectiveImmediatevalue which can used as delimiter to cut these values respectively.*/
                                    fprintf(fileWrite, "%s#~%s#~%d\n", configKey,configValue,effectiveImmediatevalue );
                                }
                                configObject = configObject->next;
                            }
                        }
                     }
                }
                else
                {
                    printf("dcmjsonparser: featureControl.features object is not present\n");
                }
            }
            else
            {
                printf("dcmjsonparser: featureControl object is not present\n");
            }
            fclose(fileWrite);
        }
        free(data);
    }
}

/**
 * @} //End of Doxygen
 */

