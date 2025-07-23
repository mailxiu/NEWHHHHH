/*    */
package com.bss.entity;

import java.util.Objects;

/*    */
/*    */
/*    */
/*    */ public class ChartCount
        /*    */ {
    /*    */   private String timeData;
    /*    */   private String referData;
    /*    */   private String volumeData;

    /*    */
    /*    */
    public ChartCount(String timeData, String referData, String volumeData) {
        /* 12 */
        this.timeData = timeData;
        this.referData = referData;
        this.volumeData = volumeData;
        /* 13 */
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.ChartCount)) return false;
        com.bss.entity.ChartCount other = (com.bss.entity.ChartCount) o;
        if (!other.canEqual(this)) return false;
        Object this$timeData = getTimeData(), other$timeData = other.getTimeData();
        if (!Objects.equals(this$timeData, other$timeData)) return false;
        Object this$referData = getReferData(), other$referData = other.getReferData();
        if (!Objects.equals(this$referData, other$referData))
            return false;
        Object this$volumeData = getVolumeData(), other$volumeData = other.getVolumeData();
        return !(!Objects.equals(this$volumeData, other$volumeData));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.ChartCount;
    }


    public String toString() {
        return "ChartCount(timeData=" + getTimeData() + ", referData=" + getReferData() + ", volumeData=" + getVolumeData() + ")";
    }

    /*    */
    /*    */
    public String getTimeData() {
        /* 16 */
        return this.timeData;
        /*    */
    }

    public void setTimeData(String timeData) {
        this.timeData = timeData;
    }

    public String getReferData() {
        /* 18 */
        return this.referData;
        /*    */
    }

    public void setReferData(String referData) {
        this.referData = referData;
    }

    public String getVolumeData() {
        /* 20 */
        return this.volumeData;
        /*    */
    }

    public void setVolumeData(String volumeData) {
        this.volumeData = volumeData;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\ChartCount.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */