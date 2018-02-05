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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <cJSON.h>
#include <errno.h>

#define RFC_CONFIG_DATA "/tmp/rfc_configdata.txt"
#define RFC_SSH_CONFIG_DATA "/tmp/RFC/.RFC_SSHWhiteList.list"

int isNodeArrayType(cJSON * const item)
{
    if (item == NULL)
    {
        return 0;
    }

    return (item->type & 0xFF) == cJSON_Array;
}

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

void main(int argc, char **argv)
{
    char *data = NULL,*dcmResponse = NULL;
    cJSON *paramObj = NULL, *childObj = NULL,*json=NULL,*configData=NULL;
    FILE *fileRead = NULL,*fileWrite =NULL;
    
    char keyValue[512]={'\0'};
    long len;
    int i;
    
    if(argc != 2)
    {
        printf("dcmjsonparser: Pass valid arguments \n");
        exit(0);
    }
    else
    {
        dcmResponse = argv[1];  
    }
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
                    char *features = cJSON_PrintUnformatted( childObj );
                    
                    for( i = 0; i < subitemSize; i++ ) 
                    {
                        cJSON* subitem = cJSON_GetArrayItem( childObj, i );

                        cJSON* featureName = cJSON_GetObjectItem(subitem, "name" );
                        cJSON* listType =  cJSON_GetObjectItem(subitem, "listType");
                        if (featureName != NULL && listType != NULL)
                        {
                            if(strcasecmp("sshwhitelist", featureName->valuestring) == 0 )
                            {
                                printf("dcmjsonparser: SSHWhiteList feature found!!\n");
                                processSSHWhiteList(subitem);
                            }
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
                                    sprintf(keyValue, "%s:%s\n", configKey,configValue );
                                    printf("dcmjsonparser: keyValue format is %s\n",keyValue);
                                    fwrite(keyValue, strlen(keyValue), 1, fileWrite);
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
