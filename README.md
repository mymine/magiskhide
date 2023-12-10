## MagiskHide

MagiskHide for Official Magisk v24.0+ as MagiskHide has been removed.

#### Configure Magisk apps

- As Magisk app does not allow you to configure denylist when zygisk is off. You must toggle Zygisk on temprorily (not reboot) to configurate denylist and toggle Zygisk off after done.

#### Configure by CLI

- You can manage denylist by `magisk --denylist`.


- To add pkg/process to denylist, use this command (example adding `com.google.android.gms.unstable`):

```
magisk --denylist add com.google.android.gms com.google.android.gms.unstable
```

- To remove pkg/process to denylist, use this command (example removing `com.google.android.gms.unstable`):

```
magisk --denylist rm com.google.android.gms com.google.android.gms.unstable
```

- Use `magisk --denylist ls` to view denylist configuration

### Bugreport

- If MagiskHide is working, you should see these line in Magisk logs:

<img src="http://huskydg.github.io/img/Screenshot_20230228-102509.png" width="60%"/>

- Only accept bugreport that MagiskHide is not working, not "MagiskHide is not able to hide xxx" issue.

- If there is any problem, use debug version and attach `/cache/magisk.log` when report bug.

### Source code

- <https://github.com/HuskyDG/MagiskHide>
