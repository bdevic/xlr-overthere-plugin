/**
 * THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
 * FOR A PARTICULAR PURPOSE. THIS CODE AND INFORMATION ARE NOT SUPPORTED BY XEBIALABS.
 */
package com.xebialabs.xlrelease.plugin.overthere;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.xebialabs.deployit.plugin.api.reflect.PropertyDescriptor;
import com.xebialabs.deployit.plugin.api.udm.ConfigurationItem;
import com.xebialabs.overthere.ConnectionOptions;
import com.xebialabs.overthere.Overthere;
import com.xebialabs.overthere.OverthereConnection;

import static com.xebialabs.overthere.ConnectionOptions.JUMPSTATION;
import static com.xebialabs.overthere.ConnectionOptions.TEMPORARY_DIRECTORY_PATH;
import static com.xebialabs.overthere.cifs.CifsConnectionBuilder.WINRS_PROXY_CONNECTION_OPTIONS;
import static com.xebialabs.overthere.cifs.CifsConnectionBuilder.WINRS_PROXY_PROTOCOL;

public class OverthereConnectionBuilder {
    public static final String PROTOCOL = "protocol";
    public static final String TEMPORARY_CI_DIRECTORY_PATH = "temporaryDirectoryPath";
    public static final String CONNECTION_OPTIONS = "connectionOptions";
    public static final String WINRS_PROXY = "winrsProxy";

    private List<String> jumpStationsSeen = new ArrayList<>();
    private List<String> winrsProxiesSeen = new ArrayList<>();

    public OverthereConnection getConnection(ConfigurationItem host) {
        return Overthere.getConnection(host.<String>getProperty(PROTOCOL), getConnectionOptions(host));
    }

    protected ConnectionOptions getConnectionOptions(ConfigurationItem host) {
        ConnectionOptions options = new ConnectionOptions();

        copyPropertiesToConnectionOptions(options, host);
        copyPropertiesMapToConnectionOptions(options, host);
        setTemporaryDirectoryPath(options, host);

        return options;
    }


    protected void copyPropertiesToConnectionOptions(ConnectionOptions options, ConfigurationItem host) {
        // copy all CI properties to connection properties
        for (PropertyDescriptor pd : host.getType().getDescriptor().getPropertyDescriptors()) {
            Object value = pd.get(host);
            setConnectionOption(options, pd.getName(), value);
        }
    }

    private void copyPropertiesMapToConnectionOptions(ConnectionOptions options, ConfigurationItem host) {
        // copy all map properties to connection properties
        Map<String, String> additionalOptions = host.getProperty(CONNECTION_OPTIONS);
        for (Map.Entry<String, String> property : additionalOptions.entrySet()) {
            setConnectionOption(options, property.getKey(), property.getValue());
        }
    }

    protected void setTemporaryDirectoryPath(final ConnectionOptions options, final ConfigurationItem host) {
        // set the temporary directory path if it has been set
        String temporaryDirectoryPath = host.getProperty(TEMPORARY_CI_DIRECTORY_PATH);
        if (temporaryDirectoryPath != null && !temporaryDirectoryPath.trim().isEmpty()) {
            setConnectionOption(options, TEMPORARY_DIRECTORY_PATH, temporaryDirectoryPath);
        }
    }

    private void setConnectionOption(ConnectionOptions options, String key, Object value) {
        if (key.equals(PROTOCOL) || key.equals(TEMPORARY_CI_DIRECTORY_PATH) || key.equals(CONNECTION_OPTIONS)) {
            return;
        }

        if (value == null || value.toString().isEmpty()) {
            return;
        }

        if (value instanceof Integer && ((Integer) value).intValue() == 0) {
            return;
        }

        switch (key) {
            case JUMPSTATION: {
                ConfigurationItem item = (ConfigurationItem) value;
                checkCircularReference(item, jumpStationsSeen, "jumpstations");

                ConnectionOptions jumpstationOptions = new ConnectionOptions();
                copyPropertiesToConnectionOptions(jumpstationOptions, item);
                options.set(key, jumpstationOptions);
                break;
            }
            case WINRS_PROXY: {
                ConfigurationItem item = (ConfigurationItem) value;
                checkCircularReference(item, winrsProxiesSeen, "winrs proxies");

                options.set(WINRS_PROXY_PROTOCOL, item.getProperty(PROTOCOL));
                ConnectionOptions winrsProxyOptions = new ConnectionOptions();
                copyPropertiesToConnectionOptions(winrsProxyOptions, item);
                options.set(WINRS_PROXY_CONNECTION_OPTIONS, winrsProxyOptions);
                break;
            }
            default:
                options.set(key, value);
                break;
        }
    }

    private void checkCircularReference(ConfigurationItem value, List<String> list, final String what) {
        if (list.contains(value.getId())) {
            list.add(value.getId());

            String loop = mkString(list, " -> ");
            throw new IllegalStateException("Detected loop in " + what + ": " + loop);
        }
        list.add(value.getId());
    }

    public static String mkString(List<String> strings, String sep) {
        if (strings.isEmpty()) return "";

        StringBuilder b = new StringBuilder(strings.get(0));
        for (int i = 1; i < strings.size(); i++) {
            b.append(sep).append(strings.get(i));
        }
        return b.toString();
    }
}
